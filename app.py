"""Protocol dashboard Flask application."""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request, send_file

from utils.browsing import browse
from utils.mail import MailError, send_mail
from utils.streaming import StreamingError, events_since, record_teardown, serve_file, start_stream

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

GITHUB_URL = "https://github.com/localrice/Protocol_visualizer"


def error_response(message: str, status: int = 400):
    return jsonify({"success": False, "error": message}), status


def requested_json() -> dict | None:
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else None


@app.get("/")
def index():
    return render_template("index.html", github_url=GITHUB_URL)


@app.post("/api/browse")
def browse_api():
    payload = requested_json()
    if not payload:
        return error_response("Send a JSON object with a URL")
    try:
        return jsonify(browse(payload.get("url", "")))
    except ValueError as exc:
        return error_response(str(exc))
    except RuntimeError as exc:
        return error_response(str(exc), 502)


@app.post("/api/mail")
def mail_api():
    payload = requested_json()
    if not payload:
        return error_response("Send a JSON object with mail fields")
    try:
        to = payload.get("to", "")
        subject = payload.get("subject", "")
        body = payload.get("body", "")
        if not all(isinstance(value, str) for value in (to, subject, body)):
            raise ValueError("Mail fields must be strings")
        return jsonify(send_mail(to.strip(), subject, body))
    except MailError as exc:
        return error_response(str(exc))


@app.post("/api/stream")
def stream_api():
    payload = requested_json() or {}
    try:
        return jsonify(start_stream(payload.get("quality", "auto")))
    except StreamingError as exc:
        return error_response(str(exc), 503)


@app.post("/api/stream/stop")
def stream_stop_api():
    record_teardown()
    return jsonify({"success": True})


@app.get("/stream/<path:filename>")
def stream_file(filename: str):
    try:
        result = serve_file(filename)
    except StreamingError as exc:
        return error_response(str(exc), 503)
    if result is None:
        return error_response("Stream resource not found", 404)
    path, content_type = result
    return send_file(path, mimetype=content_type, conditional=True)


@app.get("/api/stream/events")
def stream_events_api():
    try:
        sequence = max(0, int(request.args.get("since", "0")))
    except ValueError:
        sequence = 0
    return jsonify(events_since(sequence))


@app.errorhandler(413)
def request_too_large(_error):
    return error_response("Request body is too large", 413)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
