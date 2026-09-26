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
    payload_len = len(message_data.encode("utf-8"))

    client_port = "54210"
    server_port = "587"

    steps = []

    # 1. TCP Three-Way Handshake
    steps.append(("TCP", "transport", "client-to-server", "syn", "Client → Server", {
        "Sequence Number": "0",
        "Source Port": client_port,
        "Destination Port": server_port,
        "Window Size": "65535",
    }))
    steps.append(("TCP", "transport", "server-to-client", "syn-ack", "Server → Client", {
        "Sequence Number": "0",
        "Acknowledgment Number": "1",
        "Source Port": server_port,
        "Destination Port": client_port,
        "Window Size": "65535",
    }))
    steps.append(("TCP", "transport", "client-to-server", "ack", "Client → Server", {
        "Sequence Number": "1",
        "Acknowledgment Number": "1",
        "Source Port": client_port,
        "Destination Port": server_port,
        "State": "ESTABLISHED",
    }))

    client_seq = 1
    server_seq = 1

    # 2. Application Layer: Server Greeting
    greeting_msg = "220 smtp.gmail.com ESMTP"
    server_seq += len((greeting_msg + "\r\n").encode("utf-8"))
    steps.append(("SMTP", "application", "server-to-client", "response", greeting_msg, {}))

    # 3. EHLO & Response
    ehlo_cmd = f"EHLO {client_host}"
    client_seq += len((ehlo_cmd + "\r\n").encode("utf-8"))
    steps.append(("SMTP", "application", "client-to-server", "command", ehlo_cmd, {}))

    ehlo_resp = "250 smtp.gmail.com at your service"
    server_seq += len((ehlo_resp + "\r\n").encode("utf-8"))
    steps.append(("SMTP", "application", "server-to-client", "response", ehlo_resp, {}))

    # 4. STARTTLS & Response
    starttls_cmd = "STARTTLS"
    client_seq += len((starttls_cmd + "\r\n").encode("utf-8"))
    steps.append(("SMTP", "application", "client-to-server", "command", starttls_cmd, {}))

    starttls_resp = "220 2.0.0 Ready to start TLS"
    server_seq += len((starttls_resp + "\r\n").encode("utf-8"))
    steps.append(("SMTP", "application", "server-to-client", "response", starttls_resp, {}))

    # 5. EHLO (after TLS) & Response
    client_seq += len((ehlo_cmd + "\r\n").encode("utf-8"))
    steps.append(("SMTP", "application", "client-to-server", "command", ehlo_cmd, {}))

    server_seq += len((ehlo_resp + "\r\n").encode("utf-8"))
    steps.append(("SMTP", "application", "server-to-client", "response", ehlo_resp, {}))

    # 6. AUTH & Response
    auth_cmd = "AUTH PLAIN (credentials hidden)"
    client_seq += len("AUTH PLAIN\r\n".encode("utf-8"))
    steps.append(("SMTP", "application", "client-to-server", "command", auth_cmd, {}))

    auth_resp = "235 2.7.0 Accepted"
    server_seq += len((auth_resp + "\r\n").encode("utf-8"))
    steps.append(("SMTP", "application", "server-to-client", "response", auth_resp, {}))

    # 7. MAIL FROM & Response
    mail_from_cmd = f"MAIL FROM:<{sender_email}>"
    client_seq += len((mail_from_cmd + "\r\n").encode("utf-8"))
    steps.append(("SMTP", "application", "client-to-server", "command", mail_from_cmd, {}))

    mail_from_resp = "250 2.1.0 OK"
    server_seq += len((mail_from_resp + "\r\n").encode("utf-8"))
    steps.append(("SMTP", "application", "server-to-client", "response", mail_from_resp, {}))

    # 8. RCPT TO & Response
    rcpt_to_cmd = f"RCPT TO:<{to}>"
    client_seq += len((rcpt_to_cmd + "\r\n").encode("utf-8"))
    steps.append(("SMTP", "application", "client-to-server", "command", rcpt_to_cmd, {}))

    rcpt_to_resp = "250 2.1.5 OK"
    server_seq += len((rcpt_to_resp + "\r\n").encode("utf-8"))
    steps.append(("SMTP", "application", "server-to-client", "response", rcpt_to_resp, {}))

    # 9. DATA & Response
    data_cmd = "DATA"
    client_seq += len("DATA\r\n".encode("utf-8"))
    steps.append(("SMTP", "application", "client-to-server", "command", data_cmd, {}))

    data_resp = "354 Go ahead"
    server_seq += len((data_resp + "\r\n").encode("utf-8"))
    steps.append(("SMTP", "application", "server-to-client", "response", data_resp, {}))

    # 10. TCP DATA carrying Email Payload & SMTP Data
    steps.append(("TCP", "transport", "client-to-server", "psh", "Client → Server", {
        "Sequence Number": str(client_seq),
        "Acknowledgment Number": str(server_seq),
        "Source Port": client_port,
        "Destination Port": server_port,
        "Length": str(payload_len),
    }))
    client_seq += payload_len

    steps.append(("SMTP", "application", "client-to-server", "data", message_data, {
        "To": to,
        "Subject": subject,
        "Size": f"{payload_len} bytes",
    }))

    msg_ack_resp = "250 2.0.0 OK"
    server_seq += len((msg_ack_resp + "\r\n").encode("utf-8"))
    steps.append(("SMTP", "application", "server-to-client", "response", msg_ack_resp, {}))

    # 11. QUIT & Response
    quit_cmd = "QUIT"
    client_seq += len("QUIT\r\n".encode("utf-8"))
    steps.append(("SMTP", "application", "client-to-server", "command", quit_cmd, {}))

    quit_resp = "221 2.0.0 closing connection"
    server_seq += len((quit_resp + "\r\n").encode("utf-8"))
    steps.append(("SMTP", "application", "server-to-client", "response", quit_resp, {}))

    # 12. Four-Part TCP Teardown
    x = client_seq
    y = server_seq

    # Step 1: Client FIN, ACK (Seq = X, Ack = Y)
    steps.append(("TCP", "transport", "client-to-server", "fin-ack", "Client → Server", {
        "Sequence Number": str(x),
        "Acknowledgment Number": str(y),
        "Source Port": client_port,
        "Destination Port": server_port,
        "State": "FIN_WAIT_1",
    }))

    # Step 2: Server ACK (Seq = Y, Ack = X+1)
    steps.append(("TCP", "transport", "server-to-client", "ack", "Server → Client", {
        "Sequence Number": str(y),
        "Acknowledgment Number": str(x + 1),
        "Source Port": server_port,
        "Destination Port": client_port,
        "State": "CLOSE_WAIT",
    }))

    # Step 3: Server FIN, ACK (Seq = Y, Ack = X+1)
    steps.append(("TCP", "transport", "server-to-client", "fin-ack", "Server → Client", {
        "Sequence Number": str(y),
        "Acknowledgment Number": str(x + 1),
        "Source Port": server_port,
        "Destination Port": client_port,
        "State": "LAST_ACK",
    }))

    # Step 4: Client ACK (Seq = X+1, Ack = Y+1)
    steps.append(("TCP", "transport", "client-to-server", "ack", "Client → Server", {
        "Sequence Number": str(x + 1),
        "Acknowledgment Number": str(y + 1),
        "Source Port": client_port,
        "Destination Port": server_port,
        "State": "TIME_WAIT",
    }))

    events = []
    for seq, (proto, layer, direction, event_type, msg, fields) in enumerate(steps, start=1):
        events.append(_event(seq, direction, event_type, msg, fields=fields, delay=650, protocol=proto, layer=layer))
    return events


def send_mail(to: str, subject: str, body: str) -> dict:
    """Validate input and return the simulated SMTP protocol exchange."""
    to = to.strip()
    _validate_message(to, subject, body)
    events = _simulate_smtp_events(to, subject, body)
    return {
        "success": True,
        "activity": "mail",
        "server": "smtp.gmail.com:587",
        "events": events,
        "simulated": True,
    }

