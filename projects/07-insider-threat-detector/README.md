# Insider Threat Detector

A Windows monitoring agent written in C that reports user activity to a small Python server, which scores each event for risk, raises alerts and shows everything on a live dashboard. This started as a team project for a class; I wrote the agent, the server and the dashboard.

**Code:** [github.com/skausky/InsiderThreatDetector](https://github.com/skausky/InsiderThreatDetector)

Only for lab machines you own, with the user's knowledge. It records clipboard text, window titles and screenshots, so running it on someone else's computer would be a serious privacy problem.

## How it works

```
Windows endpoint: agent.exe (C, Win32 APIs only)
  process, USB, clipboard, window-title and network-upload monitors
  -> ring buffer -> HTTP POST every 30 s (pre-shared key header)
        |
        v
Server: server_backend.py (Flask + SQLite)
  check key -> score risk -> store -> alert by webhook or email above a threshold
        |
        v
Dashboard: one HTML page (React from a CDN, no build step), refreshes every 5 s
```

**The agent** is a single `.exe` with no dependencies. It uses `WinMain` and the `-mwindows` linker flag, so no console window appears. Each monitor is its own thread writing into a shared 1000-slot ring buffer behind a `CRITICAL_SECTION`:

- **Processes:** a Toolhelp32 snapshot every 2 s, compared with the last one to report new processes.
- **USB:** a hidden message-only window registered for device notifications, so it uses no CPU until a device is plugged in.
- **Clipboard:** checks clipboard text every 2 s against keywords like "password", "api_key" and "-----BEGIN PRIVATE KEY".
- **Window titles:** reports when the foreground window changes.
- **Uploads:** sums outgoing bytes across network interfaces every 10 s and flags spikes against a short rolling average.
- **After hours:** every event is tagged if it happens outside configured work hours.
- **Screenshots:** on high-risk events it captures the active window (`PrintWindow`, falling back to `BitBlt`), builds a BMP in memory and sends it base64-encoded with the event.

**The server** checks the agent's key, scores each event, stores it in SQLite and sends a webhook or email when the score passes a threshold (80 by default). The dashboard lists endpoints by risk and shows a live event feed. It also has a demo mode with fake events, so you can try it without an agent.

## What I learned

- **The Win32 API without a framework:** device notifications through a message-only window, `PrintWindow` failing on some composited windows (hence the `BitBlt` fallback), and wide strings everywhere.
- **Threads sharing one buffer** need a lock and a plan for when it fills up. Mine drops the oldest events rather than blocking the monitors.
- **Most of the signal is context, not single events.** A USB stick at 2 pm is normal; a USB stick, a large upload and a clipboard full of "password" at 11 pm is worth an alert. That's why scoring combines event type, keywords and time of day.

## What a defender sees

The same behaviours this tool flags are what EDR and DLP products watch for. Running the agent itself is noisy: a new unsigned executable, a hidden window, regular HTTP posts to one internal host, and screen capture API calls. A Sysmon config logging process creation (event 1) and network connections (event 3) would show it within a minute.

## Limits

- By default the agent posts over plain HTTP with one shared key in a header (there's a `USE_HTTPS` switch, off by default). That's fine on an isolated lab network; anything real would need TLS on and a key per agent.
- Scoring is hand-tuned rules, not a learned baseline per user.
