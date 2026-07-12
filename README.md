# ERPNext MCP Server

A robust, asynchronous Model Context Protocol (MCP) server that securely connects LLMs to your ERPNext instance (Self-Hosted or Frappe Cloud) via its REST API.

## Features

- **High Performance:** Uses `httpx.AsyncClient` with connection pooling to handle fast, concurrent LLM tool calls without blocking.
- **Configurable Access Control (Zoho-style):** Enforces a strict `config.json` whitelist for DocTypes and API Methods to prevent LLMs from hallucinating destructive actions.
- **Memory Safety:** Hard-caps all list queries to 1000 records to prevent massive JSON payloads from crashing your server.
- **Universal Deployment:** Run it locally (stdio) for personal R&D, or deploy it as an SSE Web Server (Server-Sent Events) via Docker for SaaS-like remote access.

## Architecture & Security

### 1. Configuration (`config.json`)
By default, the server will **reject** any request unless it explicitly matches your configuration file.
```json
{
  "readable_doctypes": ["Customer", "Sales Invoice", "Item", "Task"],
  "writable_doctypes": ["Customer", "Task"],
  "deletable_doctypes": [],
  "allowed_methods": ["erpnext.projects.doctype.task.task.set_status"],
  "mcp_tokens": [
    "YOUR_SECURE_CLIENT_TOKEN_1",
    "YOUR_SECURE_CLIENT_TOKEN_2"
  ]
}
```

### 2. API Key Best Practices
Do **NOT** use a System Manager's API Key. Create a dedicated "MCP Service User" in ERPNext and assign it a heavily restricted role (e.g., Read/Write only for Sales, Support, or specific modules). 

## Local Installation (Personal Use / R&D)

1. Set your environment variables:
   - `ERPNEXT_URL`
   - `ERPNEXT_API_KEY`
   - `ERPNEXT_API_SECRET`
2. Install dependencies:
   ```bash
   pip install -e .
   ```
3. Connect Claude Desktop (`claude_desktop_config.json`):
   ```json
   {
     "mcpServers": {
       "erpnext": {
         "command": "/path/to/your/venv/bin/erpnext-mcp",
         "env": {
           "ERPNEXT_URL": "https://your-site.com",
           "ERPNEXT_API_KEY": "your_api_key",
           "ERPNEXT_API_SECRET": "your_api_secret"
         }
       }
     }
   }
   ```

## Production VPS Deployment (SSE / SaaS Mode)

If you are hosting this on a VPS (like an Oracle ARM instance) to allow external clients to connect over the internet:

1. **Docker Compose:**
   The included `docker-compose.yml` will run the server in SSE mode on port `8000`.
   ```bash
   docker compose up -d
   ```
2. **Reverse Proxy (Caddy / Nginx):**
   You **must** place this container behind a reverse proxy. 
   - Expose the container via a domain (e.g., `mcp.extrotechs.com`).
   - The server enforces token authentication via the `TokenAuthAndRateLimitMiddleware`. Clients must send an `Authorization: Bearer YOUR_TOKEN` header connecting to the SSE stream.
3. **Internal vs External Routing:**
   - If deploying on the same VPS as your Frappe instance, set `ERPNEXT_URL=http://frontend:8080` (or whatever the docker-compose internal network URL is) to bypass the public internet and improve speed.
   - If connecting to an external client's Frappe Cloud instance, use their public URL.
