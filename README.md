# Protocol Visualizer

A web application that demonstrates network protocols in action—performing live DNS resolution and HTTP/HTTPS browsing, real-time HLS video streaming, and a simulated SMTP email protocol exchange based on an actual session captured during development. Each activity exposes both the **Application Layer** requests and the underlying **Transport Layer** (TCP / UDP) communication.

## Activities Overview

- **Browsing (Live)**: Performs real DNS resolution (via `dnspython`) and real HTTP/HTTPS requests on the server, generating a live layered protocol trace of DNS queries/responses over UDP datagrams, TCP 3-way handshake, TLS negotiation, HTTP request/response payloads, and TCP connection teardown.
- **Streaming (Live)**: Performs real HLS video streaming from the Flask server using FFmpeg, capturing live playlist (`.m3u8`) and segment (`.ts`) HTTP requests alongside the underlying TCP transport segments carrying the media payloads.
- **Mail (SMTP Simulation)**: Visualizes a step-by-step SMTP exchange (greeting, EHLO, STARTTLS, AUTH PLAIN, MAIL FROM, RCPT TO, DATA, QUIT) alongside underlying TCP connection establishment, data push segments, and graceful connection teardown.
  > *Note on Mail:* Outbound SMTP access on ports 25, 465, and 587 is blocked at the platform level on DigitalOcean VPS instances. To maintain the educational demonstration without connection failures or exposing credentials, the Mail visualizer replays a realistic protocol exchange captured during development.

## Requirements

- **Python 3.10+**
- **FFmpeg** (required for HLS video streaming)
- Python packages (from `requirements.txt`):
  - `Flask`
  - `dnspython`
  - `gunicorn`

On Ubuntu/Debian systems:
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip ffmpeg git
```

## Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/localrice/Protocol_visualizer.git
   cd Protocol_visualizer
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment variables (optional)**:
   The application works out of the box without any external credentials or configuration.
   If desired, you can customize the sender identity displayed in the simulated Mail exchange by copying `.env.example`:
   ```bash
   cp .env.example .env
   ```
   Optionally set:
   ```env
   SMTP_FROM=Kinjal's Protocol Visualizer
   SMTP_USERNAME=visualizer@kinjalboro.me
   ```

## Running

Start with Gunicorn (production):

```bash
gunicorn app:app
```

Or start the Flask development server:

```bash
python app.py
```

Open your browser and navigate to:

```text
http://127.0.0.1:5000
```

## Production Deployment (Ubuntu VPS)

Follow these steps to deploy the application as a systemd service on an Ubuntu VPS using Gunicorn.

### 1. Clone or Update the Repository

```bash
git clone https://github.com/localrice/Protocol_visualizer.git /path/to/protocol-dashboard
cd /path/to/protocol-dashboard
```

*(If updating an existing deployment, pull the latest changes: `git pull origin main`)*

### 2. Create the Python Virtual Environment

```bash
python3 -m venv venv
```

### 3. Activate the Virtual Environment

```bash
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Install FFmpeg with apt

```bash
sudo apt update
sudo apt install -y ffmpeg
```

### 6. Create and Configure `.env` (Optional)

All activities—Browsing, Streaming, and the simulated Mail exchange—run out of the box without requiring `.env`. If you wish to customize display variables (such as sender name/email):

```bash
cp .env.example .env
nano .env
```

Use standard `KEY=value` format. **Do NOT use `export`** in `.env`, as systemd's `EnvironmentFile` directive expects plain key-value entries. Set secure file permissions:

```bash
chmod 600 .env
```

### 7. Copy the Systemd Service

```bash
sudo cp deploy/protocol-dashboard.service /etc/systemd/system/protocol-dashboard.service
```

Open `/etc/systemd/system/protocol-dashboard.service` and verify `WorkingDirectory` and `PATH` match your actual project path (e.g. `/home/deploy/protocol-dashboard`). The service is pre-configured for `User=deploy`.

### 8. Reload Systemd

```bash
sudo systemctl daemon-reload
```

### 9. Enable the Service

```bash
sudo systemctl enable protocol-dashboard.service
```

### 10. Start the Service

```bash
sudo systemctl start protocol-dashboard.service
```

### 11. Check Service Status

```bash
sudo systemctl status protocol-dashboard.service
```

### 12. Test Locally

Verify that Gunicorn is serving requests locally:

```bash
curl http://127.0.0.1:5000
```

### 13. View Logs with journalctl

Follow real-time service logs:

```bash
sudo journalctl -u protocol-dashboard.service -f
```

### 14. Restart the Service After Updates

```bash
cd /path/to/protocol-dashboard
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart protocol-dashboard.service
```

To stop the service at any time:

```bash
sudo systemctl stop protocol-dashboard.service
```

---

## Cloudflare Tunnel

The application listens locally on `127.0.0.1:5000`. To route public traffic through an existing Cloudflare Tunnel (`protocol.kinjalboro.me → http://127.0.0.1:5000`):

1. Route the DNS hostname through your tunnel:
   ```bash
   cloudflared tunnel route dns <tunnel-name-or-id> protocol.kinjalboro.me
   ```

2. Add the ingress rule to your Cloudflare Tunnel configuration (`/etc/cloudflared/config.yml`):
   ```yaml
   ingress:
     - hostname: protocol.kinjalboro.me
       service: http://127.0.0.1:5000
     - service: http_status:404
   ```

3. Restart the Cloudflare Tunnel service:
   ```bash
   sudo systemctl restart cloudflared
   ```
