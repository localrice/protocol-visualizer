"""Local MP4 to HLS streaming support."""

from __future__ import annotations

import subprocess
import threading
from collections import deque
from pathlib import Path

from utils.protocol import event

BASE_DIR = Path(__file__).resolve().parent.parent
SOURCE_VIDEO = BASE_DIR / "media" / "video.mp4"
HLS_DIR = BASE_DIR / "instance" / "stream"
HLS_PLAYLIST = HLS_DIR / "playlist.m3u8"
_generation_lock = threading.Lock()
_stream_lock = threading.Lock()
_stream_events: deque[dict] = deque(maxlen=200)
_next_sequence = 1
_handshake_done = False
_client_seq = 1
_server_seq = 1

CLIENT_PORT = "51420"
SERVER_PORT = "5000"


class StreamingError(Exception):
    """A safe error raised when local HLS preparation fails."""


def _record(event_type: str, message: str, fields: dict[str, str], direction: str,
            protocol: str = "HLS", layer: str = "application") -> None:
    global _next_sequence
    _stream_events.append(event(_next_sequence, protocol, direction, event_type, message, fields, delay=650, layer=layer))
    _next_sequence += 1


def _record_handshake() -> None:
    global _handshake_done, _client_seq, _server_seq
    # 1. TCP SYN (Client -> Server)
    _record(
        "syn", "Client → Server",
        {
            "Seq": "0",
            "Src": CLIENT_PORT,
            "Dst": SERVER_PORT,
            "Window": "65535",
        },
        direction="client-to-server",
        protocol="TCP",
        layer="transport",
    )

    # 2. TCP SYN-ACK (Server -> Client)
    _record(
        "syn-ack", "Server → Client",
        {
            "Seq": "0",
            "Ack": "1",
            "Src": SERVER_PORT,
            "Dst": CLIENT_PORT,
            "Window": "65535",
        },
        direction="server-to-client",
        protocol="TCP",
        layer="transport",
    )

    # 3. TCP ACK (Client -> Server)
    _record(
        "ack", "Client → Server",
        {
            "Seq": "1",
            "Ack": "1",
            "Src": CLIENT_PORT,
            "Dst": SERVER_PORT,
            "State": "ESTABLISHED",
        },
        direction="client-to-server",
        protocol="TCP",
        layer="transport",
    )

    _handshake_done = True
    _client_seq = 1
    _server_seq = 1


def _video_encoder() -> str:
    try:
        encoders = subprocess.run(
            ["ffmpeg", "-hide_banner", "-encoders"],
            check=True, capture_output=True, text=True, timeout=10,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise StreamingError("FFmpeg is not installed on the server")
    for encoder in ("libx264", "libopenh264"):
        if encoder in encoders:
            return encoder
    raise StreamingError("FFmpeg needs an H.264 encoder for browser playback")


def ensure_hls() -> None:
    if HLS_PLAYLIST.exists() and any(HLS_DIR.glob("segment*.ts")):
        return
    if not SOURCE_VIDEO.exists():
        raise StreamingError("The local source video is missing")
    HLS_DIR.mkdir(parents=True, exist_ok=True)
    encoder = _video_encoder()
    command = [
        "ffmpeg", "-y", "-i", str(SOURCE_VIDEO),
        "-c:v", encoder, "-g", "48", "-sc_threshold", "0",
        "-c:a", "aac", "-b:a", "96k", "-f", "hls", "-hls_time", "2",
        "-hls_list_size", "0", "-hls_segment_filename", str(HLS_DIR / "segment%03d.ts"),
        str(HLS_PLAYLIST),
    ]
    with _generation_lock:
        if HLS_PLAYLIST.exists() and any(HLS_DIR.glob("segment*.ts")):
            return
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
        except FileNotFoundError as exc:
            raise StreamingError("FFmpeg is not installed on the server") from exc
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise StreamingError("FFmpeg could not create the HLS stream") from exc


def start_stream(quality: str = "auto") -> dict:
    global _next_sequence, _handshake_done, _client_seq, _server_seq
    ensure_hls()
    with _stream_lock:
        _stream_events.clear()
        _next_sequence = 1
        _handshake_done = False
        _client_seq = 1
        _server_seq = 1
        _record_handshake()
    quality = quality if quality in {"auto", "360p", "720p"} else "auto"
    return {
        "success": True,
        "activity": "streaming",
        "stream_url": "/stream/playlist.m3u8",
        "quality": quality,
        "events": [],
        "real": True,
    }


def serve_file(filename: str):
    global _client_seq, _server_seq
    ensure_hls()
    path = (HLS_DIR / filename).resolve()
    if path.parent != HLS_DIR.resolve() or path.suffix not in {".m3u8", ".ts"} or not path.is_file():
        return None
    resource = f"/stream/{filename}"
    content_type = "application/vnd.apple.mpegurl" if path.suffix == ".m3u8" else "video/mp2t"
    file_size = path.stat().st_size
    req_len = len(resource)

    with _stream_lock:
        if not _handshake_done:
            _record_handshake()

        cur_client_seq = _client_seq
        cur_server_seq = _server_seq

        # 1. Application Layer: HLS media request
        _record("request", f"GET {resource}", {
            "Resource": resource, "Content-Type": content_type
        }, "client-to-server", protocol="HLS", layer="application")

        # 2. Transport Layer: Client TCP segment carrying HTTP request
        _record("psh", "Client → Server", {
            "Seq": str(cur_client_seq),
            "Ack": str(cur_server_seq),
            "Src": CLIENT_PORT,
            "Dst": SERVER_PORT,
            "Length": str(req_len),
        }, "client-to-server", protocol="TCP", layer="transport")

        # Client sequence number advances by bytes transmitted
        _client_seq += req_len
        ack_from_server = _client_seq

        # 3. Application Layer: HTTP 200 OK response
        _record("response", "HTTP/1.1 200 OK", {
            "Content-Type": content_type, "Size": f"{file_size} bytes"
        }, "server-to-client", protocol="HLS", layer="application")

        # 4. Transport Layer: Server TCP segment delivering HTTP response
        _record("psh", "Server → Client", {
            "Seq": str(cur_server_seq),
            "Ack": str(ack_from_server),
            "Src": SERVER_PORT,
            "Dst": CLIENT_PORT,
            "Length": str(file_size),
        }, "server-to-client", protocol="TCP", layer="transport")

        # Server sequence number advances by bytes transmitted
        _server_seq += file_size

    return path, content_type


def events_since(sequence: int) -> dict:
    with _stream_lock:
        return {"events": [item for item in _stream_events if item["sequence"] > sequence]}
