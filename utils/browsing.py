"""DNS and HTTP browsing functionality."""

from __future__ import annotations

import ipaddress
import os
import socket
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

import dns.exception
import dns.resolver

from utils.protocol import event

USER_AGENT = "ProtocolDashboard/1.0"
REQUEST_TIMEOUT = 8
MAX_BODY_BYTES = 128 * 1024
DNS_RESOLVER = os.environ.get("DNS_RESOLVER", "1.1.1.1")
DNS_TIMEOUT = 3


class NoRedirectHandler(HTTPRedirectHandler):
    """Prevent urllib from following an unvalidated redirect automatically."""

    def http_error_302(self, req, fp, code, msg, headers):
        return fp

    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302
    http_error_308 = http_error_302


def is_public_ip(address: str) -> bool:
    parsed = ipaddress.ip_address(address)
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def resolve_public_host(hostname: str) -> list[str]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [DNS_RESOLVER]
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    addresses = set()
    try:
        for record_type in ("A", "AAAA"):
            try:
                answers = resolver.resolve(hostname, record_type)
            except dns.resolver.NoAnswer:
                continue
            addresses.update(answer.to_text() for answer in answers)
    except (dns.exception.DNSException, OSError) as exc:
        raise ValueError(f"DNS lookup failed for {hostname}") from exc

    addresses = sorted(addresses)
    if not addresses:
        raise ValueError(f"DNS lookup returned no addresses for {hostname}")
    if not all(is_public_ip(address) for address in addresses):
        raise ValueError("Private or internal destinations are blocked")
    return addresses


def validate_url(value: str) -> tuple[str, str, str]:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("Enter a valid HTTP or HTTPS URL")
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only HTTP and HTTPS URLs are allowed")
    if parsed.username or parsed.password:
        raise ValueError("URLs with embedded credentials are not allowed")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Enter a valid HTTP or HTTPS URL") from exc
    if port not in {None, 80, 443}:
        raise ValueError("Only standard HTTP and HTTPS ports are allowed")
    normalized = parsed.geturl()
    return normalized, parsed.hostname, parsed.path or "/"


def browse(url: str) -> dict:
    normalized_url, hostname, path = validate_url(url)
    addresses = resolve_public_host(hostname)
    scheme = urlparse(normalized_url).scheme.upper()
    target_port = 443 if scheme == "HTTPS" else 80
    client_port = 52418
    target_dest = f"{hostname}:{target_port}"

    events = []
    seq = 1

    # --- 1. TCP Three-Way Handshake ---
    events.append(event(
        seq, "TCP", "client-to-server", "syn",
        "Client → Server",
        {
            "Seq": "0",
            "Src": str(client_port),
            "Dst": str(target_port),
            "Window": "65535",
        },
        delay=600,
        layer="transport",
    ))
    seq += 1

    events.append(event(
        seq, "TCP", "server-to-client", "syn-ack",
        "Server → Client",
        {
            "Seq": "0",
            "Ack": "1",
            "Src": str(target_port),
            "Dst": str(client_port),
            "Window": "65535",
        },
        delay=600,
        layer="transport",
    ))
    seq += 1

    events.append(event(
        seq, "TCP", "client-to-server", "ack",
        "Client → Server",
        {
            "Seq": "1",
            "Ack": "1",
            "Src": str(client_port),
            "Dst": str(target_port),
            "State": "ESTABLISHED",
        },
        delay=600,
        layer="transport",
    ))
    seq += 1

    # --- 2. Live HTTP Request Execution ---
    request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    http_request = Request(normalized_url, headers=request_headers, method="GET")
    raw_req_preview = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\n\r\n"
    req_payload_len = len(raw_req_preview.encode("utf-8"))

    started = time.monotonic()
    try:
        opener = build_opener(NoRedirectHandler())
        with opener.open(http_request, timeout=REQUEST_TIMEOUT) as response:
            body = response.read(MAX_BODY_BYTES + 1)
            status = response.status
            reason = response.reason or ""
            response_headers = response.headers
            final_url = response.geturl()
    except HTTPError as exc:
        body = exc.read(MAX_BODY_BYTES + 1)
        status = exc.code
        reason = exc.reason or ""
        response_headers = exc.headers
        final_url = normalized_url
    except (TimeoutError, socket.timeout) as exc:
        raise RuntimeError("The request timed out") from exc
    except URLError as exc:
        raise RuntimeError(f"Connection failed: {exc.reason}") from exc
    except OSError as exc:
        raise RuntimeError(f"Connection failed: {exc}") from exc

    elapsed_ms = round((time.monotonic() - started) * 1000)
    content_type = response_headers.get("Content-Type", "unknown")
    content_length = response_headers.get("Content-Length", str(len(body)))
    response_fields = {
        "Status": f"{status} {reason}".strip(),
        "Content-Type": content_type,
        "Size": f"{len(body)} bytes",
    }

    request_protocol = "HTTPS" if scheme == "HTTPS" else "HTTP"

    # --- 3. Application Layer: HTTP Request ---
    events.append(event(
        seq, request_protocol, "client-to-server", "request",
        f"GET {path} HTTP/1.1",
        {
            "Host": hostname,
        },
        delay=650,
        layer="application",
    ))
    seq += 1

    # --- 4. Transport Layer: TCP Data Segment (HTTP Request) ---
    events.append(event(
        seq, "TCP", "client-to-server", "psh",
        "Client → Server",
        {
            "Seq": "1",
            "Ack": "1",
            "Src": str(client_port),
            "Dst": str(target_port),
            "Length": str(req_payload_len),
        },
        delay=600,
        layer="transport",
    ))
    seq += 1

    # --- 5. Transport Layer: Server ACK of Request ---
    events.append(event(
        seq, "TCP", "server-to-client", "ack",
        "Server → Client",
        {
            "Seq": "1",
            "Ack": str(1 + req_payload_len),
            "Src": str(target_port),
            "Dst": str(client_port),
        },
        delay=600,
        layer="transport",
    ))
    seq += 1

    # --- 6. Application Layer: HTTP Response ---
    events.append(event(
        seq, request_protocol, "server-to-client", "response",
        f"HTTP/1.1 {status} {reason}".strip(),
        response_fields,
        delay=650,
        layer="application",
    ))
    seq += 1

    # --- 7. Transport Layer: TCP Data Segment (HTTP Response Payload) ---
    resp_bytes = len(body)
    events.append(event(
        seq, "TCP", "server-to-client", "psh",
        "Server → Client",
        {
            "Seq": "1",
            "Ack": str(1 + req_payload_len),
            "Src": str(target_port),
            "Dst": str(client_port),
            "Length": str(resp_bytes),
        },
        delay=600,
        layer="transport",
    ))
    seq += 1

    # --- 8. Transport Layer: Client ACK for response data ---
    events.append(event(
        seq, "TCP", "client-to-server", "ack",
        "Client → Server",
        {
            "Seq": str(1 + req_payload_len),
            "Ack": str(1 + resp_bytes),
            "Src": str(client_port),
            "Dst": str(target_port),
        },
        delay=600,
        layer="transport",
    ))
    seq += 1

    # --- 9. Transport Layer: Four-Part TCP Teardown ---
    x = 1 + req_payload_len
    y = 1 + resp_bytes

    # Step 1: Client FIN, ACK (Seq = X, Ack = Y)
    events.append(event(
        seq, "TCP", "client-to-server", "fin-ack",
        "Client → Server",
        {
            "Seq": str(x),
            "Ack": str(y),
            "Src": str(client_port),
            "Dst": str(target_port),
            "State": "FIN_WAIT_1",
        },
        delay=600,
        layer="transport",
    ))
    seq += 1

    # Step 2: Server ACK (Seq = Y, Ack = X+1)
    events.append(event(
        seq, "TCP", "server-to-client", "ack",
        "Server → Client",
        {
            "Seq": str(y),
            "Ack": str(x + 1),
            "Src": str(target_port),
            "Dst": str(client_port),
            "State": "CLOSE_WAIT",
        },
        delay=600,
        layer="transport",
    ))
    seq += 1

    # Step 3: Server FIN, ACK (Seq = Y, Ack = X+1)
    events.append(event(
        seq, "TCP", "server-to-client", "fin-ack",
        "Server → Client",
        {
            "Seq": str(y),
            "Ack": str(x + 1),
            "Src": str(target_port),
            "Dst": str(client_port),
            "State": "LAST_ACK",
        },
        delay=600,
        layer="transport",
    ))
    seq += 1

    # Step 4: Client ACK (Seq = X+1, Ack = Y+1)
    events.append(event(
        seq, "TCP", "client-to-server", "ack",
        "Client → Server",
        {
            "Seq": str(x + 1),
            "Ack": str(y + 1),
            "Src": str(client_port),
            "Dst": str(target_port),
            "State": "TIME_WAIT",
        },
        delay=600,
        layer="transport",
    ))
    seq += 1

    return {
        "success": True,
        "activity": "browsing",
        "server": target_dest,
        "events": events,
    }

