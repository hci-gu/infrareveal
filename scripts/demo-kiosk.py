#!/usr/bin/env python3
"""Start a dedicated Chromium kiosk when the lab gateway is ready; supervise recovery."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request


def gateway_ready(url):
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/api/infrareveal/demo", timeout=5) as response:
            status = json.load(response)
        if not status.get("enabled") or not status.get("sessionId"):
            return False
        # The display's HTML must be available too, not just the backend API.
        with urllib.request.urlopen(url.rstrip("/") + "/demo", timeout=5) as response:
            return response.status == 200 and "text/html" in response.headers.get("Content-Type", "")
    except (OSError, ValueError):
        return False


def browser_command(browser, profile, url):
    return [browser, "--kiosk", "--no-first-run", "--no-default-browser-check",
            "--disable-session-crashed-bubble", "--user-data-dir=" + str(profile),
            url.rstrip("/") + "/demo"]


def stop_browser(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://10.77.0.1")
    parser.add_argument("--browser", help="Chromium/Chrome/Edge executable path")
    parser.add_argument("--profile", type=Path, default=Path.home() / ".local/share/infrareveal-kiosk")
    args = parser.parse_args()
    browser = args.browser or next((path for name in ("chromium", "chromium-browser", "google-chrome", "microsoft-edge") if (path := shutil.which(name))), None)
    if not browser:
        parser.error("install Chromium or pass --browser with the browser executable path")
    args.profile.mkdir(parents=True, exist_ok=True)
    process = None
    failures = 0
    try:
        while True:
            ready = gateway_ready(args.url)
            if ready:
                if failures >= 3:
                    stop_browser(process)
                    process = None
                failures = 0
                if process is None or process.poll() is not None:
                    print("Gateway ready; opening InfraReveal demo", flush=True)
                    process = subprocess.Popen(browser_command(browser, args.profile.resolve(), args.url), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                failures += 1
                if failures == 1:
                    print("Waiting for gateway; retrying automatically", flush=True)
            time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        stop_browser(process)


if __name__ == "__main__":
    main()
