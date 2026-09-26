"""Simulated SMTP protocol visualization based on captured development exchange."""

from __future__ import annotations

import os
import socket

from utils.protocol import event


class MailError(Exception):
    """A safe, user-facing error message without credential details."""


def _event(sequence: int, direction: str, event_type: str, message: str,
           fields: dict[str, str] | None = None, delay: int = 700,
           protocol: str = "SMTP", layer: str | None = None) -> dict:
    return event(sequence, protocol, direction, event_type, message, fields or {}, delay, layer=layer)


def _validate_message(to: str, subject: str, body: str) -> None:
    if not to or "@" not in to or len(to) > 254:
        raise MailError("Enter a recipient email address")
    if not subject.strip() or len(subject) > 200:
        raise MailError("Enter a subject up to 200 characters")
    if not body.strip() or len(body) > 4000:
        raise MailError("Enter a message body up to 4,000 characters")


def _simulate_smtp_events(to: str, subject: str, body: str) -> list[dict]:
    """Generate the simulated SMTP exchange based on the captured development session."""
    client_host = socket.getfqdn() or "localhost"

    raw_from = os.environ.get("SMTP_FROM", "Kinjal's Protocol Visualizer").strip() or "Kinjal's Protocol Visualizer"
    raw_user = os.environ.get("SMTP_USERNAME", "mortestingkarone@gmail.com").strip() or "visualizer@kinjalboro.me"

    if "@" in raw_from:
        sender_email = raw_from
        from_header = raw_from
    else:
        sender_email = raw_user if "@" in raw_user else "visualizer@kinjalboro.me"
        from_header = f"{raw_from} <{sender_email}>"

    message_data = (
        f"From: {from_header}\r\n"
        f"To: {to}\r\n"
        f"Subject: {subject}\r\n"
        f'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
        f"{body}"
    )

    steps = [
        # (protocol, layer, direction, event_type, message, fields)
        ("TCP", "transport", "client-to-server", "syn", "Client → Server", {
            "Seq": "0", "Src": "54210", "Dst": "587", "Window": "65535",
        }),
        ("TCP", "transport", "server-to-client", "syn-ack", "Server → Client", {
            "Seq": "0", "Ack": "1", "Src": "587", "Dst": "54210", "Window": "65535",
        }),
        ("TCP", "transport", "client-to-server", "ack", "Client → Server", {
            "Seq": "1", "Ack": "1", "Src": "54210", "Dst": "587", "State": "ESTABLISHED",
        }),
        ("SMTP", "application", "server-to-client", "response", "220 smtp.gmail.com ESMTP", {}),
        ("SMTP", "application", "client-to-server", "command", f"EHLO {client_host}", {}),
        ("SMTP", "application", "server-to-client", "response", "250 smtp.gmail.com at your service", {}),
        ("SMTP", "application", "client-to-server", "command", "STARTTLS", {}),
        ("SMTP", "application", "server-to-client", "response", "220 2.0.0 Ready to start TLS", {}),
        ("SMTP", "application", "client-to-server", "command", f"EHLO {client_host}", {}),
        ("SMTP", "application", "server-to-client", "response", "250 smtp.gmail.com at your service", {}),
        ("SMTP", "application", "client-to-server", "command", "AUTH PLAIN (credentials hidden)", {}),
        ("SMTP", "application", "server-to-client", "response", "235 2.7.0 Accepted", {}),
        ("SMTP", "application", "client-to-server", "command", f"MAIL FROM:<{sender_email}>", {}),
        ("SMTP", "application", "server-to-client", "response", "250 2.1.0 OK", {}),
        ("SMTP", "application", "client-to-server", "command", f"RCPT TO:<{to}>", {}),
        ("SMTP", "application", "server-to-client", "response", "250 2.1.5 OK", {}),
        ("SMTP", "application", "client-to-server", "command", "DATA", {}),
        ("SMTP", "application", "server-to-client", "response", "354 Go ahead", {}),
        ("TCP", "transport", "client-to-server", "psh", "Client → Server", {
            "Seq": "1", "Ack": "1", "Src": "54210", "Dst": "587",
            "Length": str(len(message_data.encode("utf-8"))),
        }),
        ("SMTP", "application", "client-to-server", "data", message_data, {}),
        ("SMTP", "application", "server-to-client", "response", "250 2.0.0 OK", {}),
        ("SMTP", "application", "client-to-server", "command", "QUIT", {}),
        ("SMTP", "application", "server-to-client", "response", "221 2.0.0 closing connection", {}),
        ("TCP", "transport", "client-to-server", "fin-ack", "Client → Server", {
            "Seq": "1024", "Ack": "512", "Src": "54210", "Dst": "587", "State": "FIN_WAIT_1",
        }),
        ("TCP", "transport", "server-to-client", "ack", "Server → Client", {
            "Seq": "512", "Ack": "1025", "Src": "587", "Dst": "54210", "State": "CLOSED",
        }),
    ]

    events = []
    for seq, (proto, layer, direction, event_type, msg, fields) in enumerate(steps, start=1):
        events.append(_event(seq, direction, event_type, msg, fields=fields, delay=650, protocol=proto, layer=layer))
    return events


def send_mail(to: str, subject: str, body: str) -> dict:
    """Validate input and return the simulated SMTP protocol exchange."""
    to = to.strip()
    _validate_message(to, subject, body)
    events = _simulate_smtp_events(to, subject, body)
    return {"success": True, "activity": "mail", "events": events, "simulated": True}

