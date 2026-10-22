#!/usr/bin/env python3
"""Browse public pages from the isolated client radio; write timestamps and screenshots."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
import time
from urllib.parse import urlsplit


def now_ms():
    return time.time_ns() // 1_000_000


def browse(args):
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.support.ui import WebDriverWait

    scenario = json.loads(args.scenario.read_text())
    report = {"started_ms": now_ms(), "network": json.loads((args.output / "network.json").read_text()), "visits": [], "errors": []}
    journal = args.output / "browser.json"

    def save():
        journal.write_text(json.dumps(report, indent=2) + "\n")

    try:
        for index, step in enumerate(scenario):
            if "idle_seconds" in step:
                print(f'Quiet interval: {step["idle_seconds"]} seconds (browser closed)', flush=True)
                start = now_ms()
                time.sleep(step["idle_seconds"])
                report.setdefault("idle", []).append({"start_ms": start, "end_ms": now_ms()})
                save()
                continue
            visit = {"label": step["label"], "service": step["service"], "allow_ambiguous": step.get("allow_ambiguous", False), "start_ms": now_ms(), "pages": []}
            report["visits"].append(visit)
            with tempfile.TemporaryDirectory(prefix="ir-browser-") as profile:
                options = webdriver.ChromeOptions()
                options.binary_location = shutil.which("chromium-browser") or shutil.which("chromium")
                for flag in ["--headless=new", "--disable-gpu", "--disable-dev-shm-usage", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-proxy-server", "--disable-features=DnsOverHttps,UseDnsHttpsSvcbAlpn", "--window-size=1365,900", "--user-data-dir=" + profile]:
                    options.add_argument(flag)
                options.set_capability("pageLoadStrategy", "eager")
                options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
                driver = webdriver.Chrome(service=Service(executable_path=shutil.which("chromedriver")), options=options)
                try:
                    report["browser_version"] = driver.capabilities.get("browserVersion")
                    driver.set_page_load_timeout(45)
                    for page_index, url in enumerate(step["urls"]):
                        assert urlsplit(url).scheme == "https", "Scenario URLs must use HTTPS"
                        page = {"url": url, "start_ms": now_ms()}
                        visit["pages"].append(page)
                        print(f'{visit["label"]}: {url}', flush=True)
                        driver.get_log("performance")
                        driver.get(url)
                        WebDriverWait(driver, 20).until(lambda d: d.execute_script("return document.body && document.body.innerText.length > 80"))
                        final_url = driver.current_url
                        responses = [json.loads(e["message"])["message"] for e in driver.get_log("performance")]
                        documents = [e["params"]["response"] for e in responses if e["method"] == "Network.responseReceived" and e["params"].get("type") == "Document" and e["params"]["response"]["url"].split("#")[0] == final_url.split("#")[0]]
                        response = documents[-1] if documents else {}
                        page.update(final_url=final_url, title=driver.title, status=response.get("status"), remote_ip=response.get("remoteIPAddress"))
                        assert page["status"] is not None and 200 <= page["status"] < 400, page
                        host = urlsplit(final_url).hostname
                        assert host == step["service"] or host.endswith("." + step["service"]), final_url
                        driver.save_screenshot(str(args.output / f'{index:02d}-{page_index:02d}.png'))
                        deadline = time.monotonic() + step["seconds_per_page"]
                        while time.monotonic() < deadline:
                            driver.execute_script("window.scrollBy(0, Math.max(300, innerHeight * 0.65))")
                            time.sleep(min(5, max(0, deadline - time.monotonic())))
                        page["end_ms"] = now_ms()
                        save()
                finally:
                    driver.quit()
                    visit["end_ms"] = now_ms()
                    save()
    except Exception as error:
        report["errors"].append(str(error))
        raise
    finally:
        report["ended_ms"] = now_ms()
        save()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario", type=Path, default=Path(__file__).resolve().parents[1] / "testdata/browsing-session.json")
    browse(parser.parse_args())
