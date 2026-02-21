# Muggle Power‑Up Tool (OpenClaw One‑Click Installer)

This tool installs OpenClaw on Windows with secure defaults in a single step.  
It is designed for non‑technical users: run it, wait, then launch OpenClaw safely.

## What This Does
- Downloads the official OpenClaw Windows package.
- Verifies the download with an official SHA‑256 checksum.
- Installs OpenClaw to your computer.
- Creates a secure, local‑only configuration.
- Generates local tokens on your machine (no keys are shipped inside this installer).
- Creates a safe launcher that runs a first‑launch security audit.

## System Requirements
- Windows 10 or 11
- Python 3.11 or newer
- Internet connection (for downloading OpenClaw)

## How To Use (Step‑By‑Step)
1. Download this installer file: `install_openclaw.py`
2. Double‑click it.  
   If Windows asks what to use, select Python.
3. Wait for the installer to finish.  
   You’ll see status messages like `[ok]` as it runs.
4. Open the install folder and double‑click:  
   `Launch OpenClaw Secure.bat`

That’s it. OpenClaw will start with a hardened local security profile.

## Where It Installs
If you are running as Administrator:
- `C:\Program Files\OpenClaw`

If not:
- `%LOCALAPPDATA%\OpenClaw`

## What Gets Created
Inside the install folder:
- `.env` (local tokens and safe defaults)
- `config\security.local.json` (hardened security profile)
- `Launch OpenClaw Secure.bat` (safe startup wrapper)
- `README_FIRST_RUN.txt` (short usage notes)

## Security Notes (Plain Language)
- OpenClaw listens only on your computer (`127.0.0.1`).
- Remote access is disabled by default.
- Tokens are generated locally on your device.
- A strict security audit runs the first time you launch.

Official reference: `https://docs.openclaw.ai/gateway/security`

## Troubleshooting
- **“Python not found”**: Install Python 3.11+ from python.org, then retry.
- **“Checksum mismatch”**: The download was corrupted or blocked. Retry the installer.
- **“Git is required but not found”**: The installer will try to install Git automatically.

## Developer / Packaging
To build a standalone executable:
```bash
pyinstaller --onefile install_openclaw.py
```

---
If you need help, open an issue in this repository and describe what you saw on screen.
