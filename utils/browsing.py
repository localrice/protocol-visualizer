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

    # --- 1. DNS Resolution (Application: DNS, Transport: UDP) ---
    events.append(event(
        seq, "UDP", "client-to-server", "datagram",
        f"Datagram: Client → Resolver {DNS_RESOLVER}:53 [UDP] Len=39",
        {
            "Transport": "UDP",
            "Source Port": "53124",
            "Destination Port": "53",
            "Length": "39 bytes",
            "Description": f"UDP datagram transmitting DNS query for {hostname}",
        },
        delay=600,
        layer="transport",
    ))
    seq += 1

    events.append(event(
        seq, "DNS", "client-to-server", "query",
        f"DNS Query: A {hostname}",
        {
            "Name": hostname,
            "Type": "A / AAAA",
            "Resolver": f"Recursive Resolver {DNS_RESOLVER}:53",
        },
        delay=600,
        layer="application",
    ))
    seq += 1

    events.append(event(
        seq, "UDP", "server-to-client", "datagram",
        f"Datagram: Resolver {DNS_RESOLVER}:53 → Client [UDP] Len=75",
        {
            "Transport": "UDP",
            "Source Port": "53",
            "Destination Port": "53124",
            "Length": "75 bytes",
            "Description": "UDP datagram carrying DNS resolution response",
        },
        delay=600,
        layer="transport",
    ))
    seq += 1

    events.append(event(
        seq, "DNS", "server-to-client", "response",
        "DNS Response: NOERROR",
        {
            "Resolver": f"Recursive Resolver {DNS_RESOLVER}:53",
            "Answer": ", ".join(addresses),
            "Status": "resolved",
        },
        delay=600,
        layer="application",
    ))
    seq += 1

    # --- 2. TCP Three-Way Handshake (Transport: TCP) ---
    events.append(event(
        seq, "TCP", "client-to-server", "syn",
        f"Client → Server [SYN] Seq=0 Win=65535 Len=0 ({target_dest})",
        {
            "Transport": "TCP",
            "Flags": "SYN",
            "Source Port": str(client_port),
            "Destination Port": str(target_port),
            "Sequence Number": "0 (Relative)",
            "Acknowledgment Number": "0",
            "Window Size": "65535",
            "Description": f"TCP connection establishment: Client initiates 3-way handshake to {target_dest}",
        },
        delay=650,
        layer="transport",
    ))
    seq += 1

    events.append(event(
        seq, "TCP", "server-to-client", "syn-ack",
        f"Server → Client [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0",
        {
            "Transport": "TCP",
            "Flags": "SYN, ACK",
            "Source Port": str(target_port),
            "Destination Port": str(client_port),
            "Sequence Number": "0 (Relative)",
            "Acknowledgment Number": "1 (Acknowledges Client SYN)",
            "Window Size": "65535",
            "Description": "Server confirms connection request with SYN-ACK",
        },
        delay=650,
        layer="transport",
    ))
    seq += 1

    events.append(event(
        seq, "TCP", "client-to-server", "ack",
        f"Client → Server [ACK] Seq=1 Ack=1 Win=65535 Len=0",
        {
            "Transport": "TCP",
            "Flags": "ACK",
            "Source Port": str(client_port),
            "Destination Port": str(target_port),
            "Sequence Number": "1",
            "Acknowledgment Number": "1",
            "State": "ESTABLISHED",
            "Description": "Three-way handshake complete; TCP connection established",
        },
        delay=650,
        layer="transport",
    ))
    seq += 1

    # --- 3. TLS Handshake (if HTTPS) ---
    if scheme == "HTTPS":
        events.append(event(
            seq, "TLS", "client-to-server", "handshake",
            "TLS handshake",
            {
                "Visibility": "Encrypted application data follows; no plaintext wire capture.",
                "Transport": f"HTTPS (TCP/{target_port})",
            },
            delay=700,
            layer="application",
        ))
        seq += 1

    # --- 4. Live HTTP Request Execution ---
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
        "Content-Length": content_length,
        "Elapsed": f"{elapsed_ms} ms",
    }
    if response_headers.get("Server"):
        response_fields["Server"] = response_headers["Server"]
    if 300 <= status < 400:
        response_fields["Location"] = response_headers.get("Location", "not provided")
    if len(body) > MAX_BODY_BYTES:
        response_fields["Body"] = f"truncated at {MAX_BODY_BYTES} bytes"

    request_protocol = "HTTPS" if scheme == "HTTPS" else "HTTP"

    # --- 5. Application Layer: HTTP Request ---
    events.append(event(
        seq, request_protocol, "client-to-server", "request",
        f"GET {path} HTTP/1.1",
        {
            "Host": hostname,
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Target": final_url,
            "Capture": "Request metadata from the HTTP client",
        },
        delay=700,
        layer="application",
    ))
    seq += 1

    # --- 6. Transport Layer: TCP Data Segment (HTTP Request) ---
    events.append(event(
        seq, "TCP", "client-to-server", "psh",
        f"Client → Server [PSH, ACK] Seq=1 Ack=1 Len={req_payload_len}",
        {
            "Transport": "TCP",
            "Flags": "PSH, ACK",
            "Source Port": str(client_port),
            "Destination Port": str(target_port),
            "Sequence Number": "1",
            "Acknowledgment Number": "1",
            "Payload Length": f"{req_payload_len} bytes",
            "Segment": f"Carrying HTTP request payload (GET {path})",
            "Description": "TCP segment pushes HTTP request to server socket",
        },
        delay=650,
        layer="transport",
    ))
    seq += 1

    events.append(event(
        seq, "TCP", "server-to-client", "ack",
        f"Server → Client [ACK] Seq=1 Ack={1 + req_payload_len} Win=65535 Len=0",
        {
            "Transport": "TCP",
            "Flags": "ACK",
            "Source Port": str(target_port),
            "Destination Port": str(client_port),
            "Sequence Number": "1",
            "Acknowledgment Number": str(1 + req_payload_len),
            "Description": "Server acknowledges receipt of HTTP request data bytes",
        },
        delay=650,
        layer="transport",
    ))
    seq += 1

    # --- 7. Transport Layer: TCP Data Segment (HTTP Response) ---
    resp_bytes = len(body)
    events.append(event(
        seq, "TCP", "server-to-client", "psh",
        f"Server → Client [PSH, ACK] Seq=1 Ack={1 + req_payload_len} Len={resp_bytes}",
        {
            "Transport": "TCP",
            "Flags": "PSH, ACK",
            "Source Port": str(target_port),
            "Destination Port": str(client_port),
            "Sequence Number": "1",
            "Acknowledgment Number": str(1 + req_payload_len),
            "Payload Length": f"{resp_bytes} bytes",
            "Segment": f"Carrying HTTP response payload ({status} {reason})",
            "Description": "Server returns HTTP response payload across TCP stream",
        },
        delay=650,
        layer="transport",
    ))
    seq += 1

    # --- 8. Application Layer: HTTP Response ---
    events.append(event(
        seq, request_protocol, "server-to-client", "response",
        f"HTTP/1.1 {status} {reason}".strip(),
        response_fields,
        delay=700,
        layer="application",
    ))
    seq += 1

    # --- 9. Transport Layer: Client ACK for response data ---
    events.append(event(
        seq, "TCP", "client-to-server", "ack",
        f"Client → Server [ACK] Seq={1 + req_payload_len} Ack={1 + resp_bytes} Win=65535 Len=0",
        {
            "Transport": "TCP",
            "Flags": "ACK",
            "Source Port": str(client_port),
            "Destination Port": str(target_port),
            "Sequence Number": str(1 + req_payload_len),
            "Acknowledgment Number": str(1 + resp_bytes),
            "Description": "Client acknowledges receipt of HTTP response bytes",
        },
        delay=650,
        layer="transport",
    ))
    seq += 1

    # --- 10. Transport Layer: TCP Connection Teardown ---
    events.append(event(
        seq, "TCP", "client-to-server", "fin-ack",
        f"Client → Server [FIN, ACK] Seq={1 + req_payload_len} Ack={1 + resp_bytes} Len=0",
        {
            "Transport": "TCP",
            "Flags": "FIN, ACK",
            "Source Port": str(client_port),
            "Destination Port": str(target_port),
            "State": "FIN_WAIT_1",
            "Description": "Client initiates graceful TCP connection teardown",
        },
        delay=650,
        layer="transport",
    ))
    seq += 1

    events.append(event(
        seq, "TCP", "server-to-client", "ack",
        f"Server → Client [ACK] Seq={1 + resp_bytes} Ack={2 + req_payload_len} Win=65535 Len=0",
        {
            "Transport": "TCP",
            "Flags": "ACK",
            "Source Port": str(target_port),
            "Destination Port": str(client_port),
            "State": "CLOSE_WAIT / FIN_WAIT_2",
            "Description": "Server acknowledges connection teardown",
        },
        delay=650,
        layer="transport",
    ))

    return {"success": True, "activity": "browsing", "events": events}

