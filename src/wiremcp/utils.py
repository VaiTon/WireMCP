import os
import platform
import shutil
import subprocess
import sys


def log(*args, **kwargs):
    """Log messages to stderr."""
    print(*args, file=sys.stderr, **kwargs)


def find_tshark() -> str:
    """Locate the tshark binary, searching common paths if not in PATH."""
    tshark = shutil.which("tshark")
    if tshark:
        log(f"Found tshark at: {tshark}")
        return tshark

    log("which failed to find tshark")
    fallbacks = (
        [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
        ]
        if platform.system() == "Windows"
        else [
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/opt/homebrew/bin/tshark",
            "/Applications/Wireshark.app/Contents/MacOS/tshark",
        ]
    )
    for path in fallbacks:
        if os.path.exists(path):
            try:
                subprocess.run(
                    [path, "-v"],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                log(f"Found tshark at fallback: {path}")
                return path
            except Exception as e:
                log(f"Fallback {path} failed: {e}")
    raise RuntimeError(
        "tshark not found. Please install Wireshark (https://www.wireshark.org/download.html) and ensure tshark is in your PATH."
    )


def run_tshark(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    tshark_path = find_tshark()
    env = os.environ.copy()
    env["PATH"] = env.get("PATH", "") + ":/usr/bin:/usr/local/bin:/opt/homebrew/bin"
    cmd = [tshark_path] + args
    log(f"Running: {' '.join(cmd)}")
    return subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, **kwargs
    )


def safe_unlink(path):
    try:
        os.unlink(path)
    except Exception as e:
        log(f"Failed to delete {path}: {e}")
