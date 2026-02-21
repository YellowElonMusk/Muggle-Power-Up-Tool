#!/usr/bin/env python3
"""
One-click OpenClaw installer for Windows (Python 3.11+).

Package into a standalone executable with:
    pyinstaller --onefile install_openclaw.py
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import textwrap
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

# Official references
OFFICIAL_SECURITY_DOC_URL = "https://docs.openclaw.ai/gateway/security"

# Official download locations (primary + fallback mirror)
OFFICIAL_RELEASE_ZIP_URL = "https://downloads.openclaw.ai/releases/openclaw-windows-x64.zip"
OFFICIAL_RELEASE_SHA256_URL = "https://downloads.openclaw.ai/releases/openclaw-windows-x64.zip.sha256"
OFFICIAL_RELEASE_MIRROR_ZIP_URL = (
    "https://github.com/OpenClawAI/OpenClaw/releases/latest/download/openclaw-windows-x64.zip"
)
OFFICIAL_RELEASE_MIRROR_SHA256_URL = (
    "https://github.com/OpenClawAI/OpenClaw/releases/latest/download/openclaw-windows-x64.zip.sha256"
)

ALLOWED_DOWNLOAD_HOSTS = {
    "downloads.openclaw.ai",
    "github.com",
    "objects.githubusercontent.com",
}

INSTALL_FOLDER_NAME = "OpenClaw"
PRIMARY_INSTALL_DIR = Path(r"C:\Program Files") / INSTALL_FOLDER_NAME
FALLBACK_INSTALL_DIR = Path(os.getenv("LOCALAPPDATA", str(Path.home()))) / INSTALL_FOLDER_NAME


class InstallError(RuntimeError):
    """Raised for expected installer failures with clear messages."""


@dataclass(frozen=True)
class ReleaseSource:
    zip_url: str
    sha256_url: str


RELEASE_SOURCES: tuple[ReleaseSource, ...] = (
    ReleaseSource(OFFICIAL_RELEASE_ZIP_URL, OFFICIAL_RELEASE_SHA256_URL),
    ReleaseSource(OFFICIAL_RELEASE_MIRROR_ZIP_URL, OFFICIAL_RELEASE_MIRROR_SHA256_URL),
)


def print_step(step_no: int, total_steps: int, message: str) -> None:
    print(f"\n[{step_no}/{total_steps}] {message}")


def print_info(message: str) -> None:
    print(f"  - {message}")


def print_ok(message: str) -> None:
    print(f"  [ok] {message}")


def print_error(message: str) -> None:
    print(f"  [error] {message}")


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def validate_official_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise InstallError(f"Refusing non-HTTPS URL: {url}")
    if not parsed.hostname or parsed.hostname.lower() not in ALLOWED_DOWNLOAD_HOSTS:
        raise InstallError(f"Refusing non-official download host: {url}")


def run_command(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=True, shell=False)
    if check and result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip() or "No output provided."
        raise InstallError(
            f"Command failed ({result.returncode}): {' '.join(command)}\n{details}"
        )
    return result


def download_file(url: str, destination: Path) -> None:
    validate_official_url(url)
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "OpenClaw-Installer/1.1"})
        with urllib.request.urlopen(request, timeout=120) as response:
            if response.status >= 400:
                raise InstallError(f"HTTP {response.status} while downloading {url}")

            total = response.headers.get("Content-Length")
            total_bytes = int(total) if total and total.isdigit() else None
            downloaded = 0
            with destination.open("wb") as out_file:
                while True:
                    chunk = response.read(1024 * 128)
                    if not chunk:
                        break
                    out_file.write(chunk)
                    downloaded += len(chunk)
                    if total_bytes and downloaded % (1024 * 1024) < len(chunk):
                        percent = min(100, int(downloaded * 100 / total_bytes))
                        print_info(f"Download progress: {percent}%")
    except urllib.error.URLError as exc:
        raise InstallError(f"Failed to download {url}: {exc}") from exc


def parse_sha256_file(file_path: Path) -> str:
    content = file_path.read_text(encoding="utf-8", errors="ignore").strip()
    if not content:
        raise InstallError("Official checksum file is empty.")

    first_token = content.split()[0].strip().lower()
    if len(first_token) != 64 or any(c not in "0123456789abcdef" for c in first_token):
        raise InstallError("Checksum file did not contain a valid SHA-256 value.")
    return first_token


def compute_sha256(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_pip_available() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "pip", "--version"],
        text=True,
        capture_output=True,
        shell=False,
    )
    if result.returncode == 0:
        return

    print_info("pip not found; bootstrapping via ensurepip...")
    run_command([sys.executable, "-m", "ensurepip", "--upgrade"])


def install_python_dependencies(install_dir: Path) -> None:
    req_files = [install_dir / "requirements.txt", install_dir / "gateway" / "requirements.txt"]
    req_file = next((path for path in req_files if path.exists()), None)
    if not req_file:
        print_ok("No Python requirements file detected. Skipping Python dependency install.")
        return

    ensure_pip_available()
    print_info("Installing required Python packages (this may take a few minutes)...")
    run_command([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
    run_command([sys.executable, "-m", "pip", "install", "-r", str(req_file)])
    print_ok(f"Python dependencies installed from: {req_file}")


def ensure_git_if_needed(extract_dir: Path) -> None:
    git_hint_files = [
        extract_dir / ".gitmodules",
        extract_dir / "tools" / "requires_git.txt",
    ]
    git_needed = any(path.exists() for path in git_hint_files)
    if not git_needed:
        print_ok("Git is not required for this package.")
        return

    if shutil.which("git"):
        print_ok("Git is already installed.")
        return

    print_info("Git is required but not found. Attempting silent installation via winget...")
    if not shutil.which("winget"):
        raise InstallError("Git is required but winget is unavailable for automatic installation.")

    run_command(
        [
            "winget",
            "install",
            "--id",
            "Git.Git",
            "--accept-package-agreements",
            "--accept-source-agreements",
            "--silent",
            "--disable-interactivity",
        ]
    )

    if not shutil.which("git"):
        raise InstallError("Git installation completed but git.exe was not found in PATH.")
    print_ok("Git installed successfully.")


def choose_install_dir() -> Path:
    return PRIMARY_INSTALL_DIR if is_admin() else FALLBACK_INSTALL_DIR


def ensure_clean_install_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def safe_extract_zip(zip_path: Path, destination: Path) -> None:
    with zipfile.ZipFile(zip_path, "r") as archive:
        for member in archive.infolist():
            member_path = PurePosixPath(member.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise InstallError(f"Unsafe archive path detected: {member.filename}")
        archive.extractall(destination)


def extract_release(archive_path: Path, install_dir: Path) -> None:
    if install_dir.exists() and any(install_dir.iterdir()):
        backup_dir = install_dir.with_name(f"{install_dir.name}-backup")
        if backup_dir.exists():
            shutil.rmtree(backup_dir, ignore_errors=True)
        shutil.move(str(install_dir), str(backup_dir))
        print_info(f"Existing installation backed up to: {backup_dir}")

    ensure_clean_install_dir(install_dir)
    try:
        safe_extract_zip(archive_path, install_dir)
    except zipfile.BadZipFile as exc:
        raise InstallError("Downloaded file is not a valid ZIP archive.") from exc


def write_env_file(install_dir: Path, local_token: str, admin_token: str) -> Path:
    env_path = install_dir / ".env"
    env_contents = textwrap.dedent(
        f"""\
        # Auto-generated by OpenClaw installer
        OPENCLAW_BIND_HOST=127.0.0.1
        OPENCLAW_BIND_PORT=3434
        OPENCLAW_AUTH_REQUIRED=true
        OPENCLAW_LOCAL_TOKEN={local_token}
        OPENCLAW_ADMIN_TOKEN={admin_token}
        OPENCLAW_ALLOW_REMOTE=false
        OPENCLAW_TELEMETRY_OPTOUT=true
        OPENCLAW_NO_SUDO=true
        OPENCLAW_DISABLE_DANGEROUS_TOOLS=true
        OPENCLAW_DISABLE_SHELL_TOOLS=true
        OPENCLAW_AUDIT_ON_START=true
        """
    )
    env_path.write_text(env_contents, encoding="utf-8")
    return env_path


def write_security_config(install_dir: Path, local_token: str, admin_token: str) -> Path:
    config = {
        "security": {
            "reference": OFFICIAL_SECURITY_DOC_URL,
            "auth": {
                "required": True,
                "token_mode": "local",
                "local_token": local_token,
                "admin_token": admin_token,
                "rotate_on_compromise": True,
            },
            "network": {
                "bind_host": "127.0.0.1",
                "bind_port": 3434,
                "allow_remote": False,
                "allow_cors": False,
            },
            "permissions": {
                "allow_elevated_commands": False,
                "allow_shell_execution": False,
                "allow_filesystem_write_outside_workspace": False,
                "allow_untrusted_plugins": False,
                "require_explicit_tool_allowlist": True,
            },
            "audit": {
                "enabled": True,
                "auto_run_on_first_launch": True,
                "level": "strict",
            },
        },
        "tools": {
            "enabled": ["read", "search", "safe-http"],
            "disabled": [
                "shell",
                "powershell",
                "exec",
                "sudo",
                "registry-write",
                "network-tunnel",
                "plugin-install",
            ],
        },
    }
    config_dir = install_dir / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "security.local.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config_path


def find_openclaw_executable(install_dir: Path) -> Path:
    candidates = [
        install_dir / "openclaw.exe",
        install_dir / "bin" / "openclaw.exe",
        install_dir / "OpenClaw.exe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate

    found = sorted(install_dir.rglob("openclaw*.exe"))
    if found:
        return found[0]
    raise InstallError("Installed package did not contain openclaw.exe.")


def create_first_launch_wrapper(install_dir: Path, openclaw_exe: Path) -> Path:
    wrapper_path = install_dir / "Launch OpenClaw Secure.bat"
    first_run_flag = install_dir / ".first_audit_done"
    security_config = install_dir / "config" / "security.local.json"

    script = textwrap.dedent(
        f"""\
        @echo off
        setlocal enableextensions

        set "OPENCLAW_HOME={install_dir}"
        set "OPENCLAW_SECURITY_CONFIG={security_config}"

        if not exist "{first_run_flag}" (
            echo Running first-launch OpenClaw security audit...
            "{openclaw_exe}" security-audit --config "%OPENCLAW_SECURITY_CONFIG%" --strict
            if errorlevel 1 (
                echo Security audit failed. OpenClaw will not start until this is resolved.
                pause
                exit /b 1
            )
            echo audit-ok>"{first_run_flag}"
        )

        echo Starting OpenClaw with hardened local security profile...
        "{openclaw_exe}" gateway start --config "%OPENCLAW_SECURITY_CONFIG%"
        exit /b %errorlevel%
        """
    )
    wrapper_path.write_text(script, encoding="utf-8")
    return wrapper_path


def download_and_verify_release(tmp_dir: Path) -> Path:
    errors: list[str] = []

    for index, source in enumerate(RELEASE_SOURCES, start=1):
        parsed = urllib.parse.urlparse(source.zip_url)
        filename = Path(parsed.path).name or f"openclaw-{index}.zip"
        zip_path = tmp_dir / filename
        checksum_path = tmp_dir / f"{filename}.sha256"

        try:
            print_info(f"Downloading package from: {source.zip_url}")
            download_file(source.zip_url, zip_path)

            print_info(f"Downloading checksum from: {source.sha256_url}")
            download_file(source.sha256_url, checksum_path)

            expected = parse_sha256_file(checksum_path)
            actual = compute_sha256(zip_path)
            if actual.lower() != expected.lower():
                raise InstallError(f"Checksum mismatch. Expected {expected}, got {actual}.")

            print_ok("Checksum verification passed.")
            return zip_path
        except InstallError as exc:
            errors.append(f"{source.zip_url} -> {exc}")
            if index < len(RELEASE_SOURCES):
                print_info("Download source failed; trying official fallback mirror...")

    raise InstallError("All official download sources failed:\n- " + "\n- ".join(errors))


def write_readme(install_dir: Path, launcher_path: Path) -> None:
    readme = install_dir / "README_FIRST_RUN.txt"
    readme.write_text(
        textwrap.dedent(
            f"""\
            OpenClaw has been installed with secure defaults.

            Start OpenClaw using:
              {launcher_path}

            Security profile reference:
              {OFFICIAL_SECURITY_DOC_URL}

            Notes:
            - Tokens were generated locally on this machine.
            - No sensitive API keys are embedded in this installer.
            - First launch automatically runs a strict security audit.
            """
        ),
        encoding="utf-8",
    )


def main() -> int:
    total_steps = 10
    print("OpenClaw One-Click Installer (Windows)")
    print("This installer uses secure defaults, local tokens, and first-run auditing.")

    temp_dir_path: Path | None = None
    try:
        print_step(1, total_steps, "Checking platform compatibility")
        if not is_windows():
            raise InstallError("This installer is for Windows only.")
        print_ok(f"Windows detected: {sys.getwindowsversion()}")

        print_step(2, total_steps, "Preparing temporary workspace")
        temp_dir_path = Path(tempfile.mkdtemp(prefix="openclaw-install-"))
        print_ok(f"Temporary folder: {temp_dir_path}")

        print_step(3, total_steps, "Downloading OpenClaw and official checksum")
        archive_path = download_and_verify_release(temp_dir_path)

        print_step(4, total_steps, "Selecting install folder")
        install_dir = choose_install_dir()
        print_ok(f"Install folder: {install_dir}")
        if install_dir == FALLBACK_INSTALL_DIR:
            print_info("Admin rights not detected; using per-user install location.")

        print_step(5, total_steps, "Extracting OpenClaw package")
        extract_release(archive_path, install_dir)
        print_ok("Package extracted.")

        print_step(6, total_steps, "Installing required Python dependencies")
        install_python_dependencies(install_dir)

        print_step(7, total_steps, "Installing optional system dependencies if required")
        ensure_git_if_needed(install_dir)

        print_step(8, total_steps, "Applying official security configuration")
        local_token = secrets.token_urlsafe(32)
        admin_token = secrets.token_urlsafe(48)
        env_path = write_env_file(install_dir, local_token, admin_token)
        config_path = write_security_config(install_dir, local_token, admin_token)
        print_ok(f"Environment config written: {env_path}")
        print_ok(f"Security config written: {config_path}")

        print_step(9, total_steps, "Configuring automatic first-launch security audit")
        openclaw_exe = find_openclaw_executable(install_dir)
        launcher_path = create_first_launch_wrapper(install_dir, openclaw_exe)
        print_ok(f"Secure launcher created: {launcher_path}")

        print_step(10, total_steps, "Finalizing installation")
        write_readme(install_dir, launcher_path)
        print_ok("Installation completed successfully.")
        print("\nDouble-click 'Launch OpenClaw Secure.bat' to start OpenClaw safely.")
        return 0

    except InstallError as exc:
        print_error(str(exc))
        print("\nInstallation did not complete.")
        return 1
    except Exception as exc:
        print_error(f"Unexpected error: {exc}")
        print("\nInstallation did not complete.")
        return 1
    finally:
        if temp_dir_path:
            shutil.rmtree(temp_dir_path, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

