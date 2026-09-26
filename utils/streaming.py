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
_stream_events: deque[dict] = deque(maxlen=100)
_next_sequence = 1


class StreamingError(Exception):
    """A safe error raised when local HLS preparation fails."""


def _record(event_type: str, message: str, fields: dict[str, str], direction: str,
            protocol: str = "HLS", layer: str = "application") -> None:
    global _next_sequence
    _stream_events.append(event(_next_sequence, protocol, direction, event_type, message, fields, delay=650, layer=layer))
    _next_sequence += 1


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
    global _next_sequence
    ensure_hls()
    _stream_events.clear()
    _next_sequence = 1
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
    ensure_hls()
    path = (HLS_DIR / filename).resolve()
    if path.parent != HLS_DIR.resolve() or path.suffix not in {".m3u8", ".ts"} or not path.is_file():
        return None
    resource = f"/stream/{filename}"
    content_type = "application/vnd.apple.mpegurl" if path.suffix == ".m3u8" else "video/mp2t"
    file_size = path.stat().st_size

    # 1. Application Layer: HLS media request
    _record("request", f"GET {resource}", {
        "Resource": resource, "Content-Type": content_type
    }, "client-to-server", protocol="HLS", layer="application")

    # 2. Transport Layer: Client TCP segment pushing request
    _record("psh", "Client → Server", {
        "Seq": "1", "Ack": "1", "Src": "51420", "Dst": "5000",
        "Length": str(len(resource)),
    }, "client-to-server", protocol="TCP", layer="transport")

    # 3. Transport Layer: Server TCP segment delivering payload
    _record("psh", "Server → Client", {
        "Seq": "1", "Ack": "1", "Src": "5000", "Dst": "51420",
        "Length": str(file_size),
    }, "server-to-client", protocol="TCP", layer="transport")

    # 4. Application Layer: HTTP 200 OK response
    _record("response", "HTTP/1.1 200 OK", {
        "Content-Type": content_type, "Size": f"{file_size} bytes"
    }, "server-to-client", protocol="HLS", layer="application")

    return path, content_type


def events_since(sequence: int) -> dict:
    return {"events": [item for item in _stream_events if item["sequence"] > sequence]}
