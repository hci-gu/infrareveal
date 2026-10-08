#!/usr/bin/env python3
"""Compare physical/nonblank text lines, including every nonignored new file."""
import argparse
import io
import json
from pathlib import Path
import subprocess
import tarfile


def git(*args):
    return subprocess.check_output(["git", *args])


def category(name):
    path = Path(name)
    if name.startswith("docs/") or path.suffix in {".md", ".mdx", ".rst"} or name in {
        "report.html", "updated-design-report.html",
    }:
        return "Documentation"
    if path.name in {"pnpm-lock.yaml", "package-lock.json", "go.sum"}:
        return "Dependency locks"
    if name.startswith("pocketbase/migrations/"):
        return "Historical migrations"
    if name.startswith("testdata/"):
        return "Contract fixture data"
    if (name.endswith("_test.go") or ".test." in path.name or ".spec." in path.name
            or "/test-support/" in name or name.startswith(("pocketbase/testsupport/", "scripts/test-", "dashboard/scripts/check-"))
            or name in {"scripts/check-proxy-lab-privacy.sh", "scripts/validate-proxy-lab.sh", "scripts/count-loc.py"}):
        return "Tests and verification tools"
    if path.suffix in {".go", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".sh", ".css", ".html"}:
        return "Production source"
    if "/public/" in name or path.suffix in {".svg", ".geojson"} or name in {
        "dashboard/src/map/data/countries.json", "pocketbase/observer/domain_groups.json",
    }:
        return "Static assets and domain data"
    return "Build and configuration"


def inventory(entries):
    return {name: {"category": category(name), "lines": len(data.splitlines()),
                   "nonblank": sum(bool(line.strip()) for line in data.splitlines())}
            for name, data in entries if b"\0" not in data}


def totals(files, field):
    result = {}
    for entry in files.values():
        key = entry["category"]
        result[key] = result.get(key, 0) + entry[field]
    result["All non-documentation"] = sum(value for key, value in result.items() if key != "Documentation")
    result["Maintained scope"] = sum(result.get(key, 0) for key in (
        "Production source", "Tests and verification tools", "Build and configuration", "Contract fixture data"))
    return result


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--base", default="HEAD", help="Git revision to compare with the complete working tree")
parser.add_argument("--json", action="store_true", help="Include per-file inventories in machine-readable output")
args = parser.parse_args()
root = Path(git("rev-parse", "--show-toplevel").decode().strip())
with tarfile.open(fileobj=io.BytesIO(git("archive", args.base))) as archive:
    before = inventory((entry.name, archive.extractfile(entry).read()) for entry in archive if entry.isfile())
paths = sorted(set(git("ls-files", "--full-name", "--cached", "--others", "--exclude-standard", "-z").decode().split("\0")) - {""})
after = inventory((name, (root / name).read_bytes()) for name in paths if (root / name).is_file())
report = {"base": git("rev-parse", args.base).decode().strip(), "before": before, "after": after}
report["totals"] = {field: {"before": totals(before, field), "after": totals(after, field)} for field in ("lines", "nonblank")}
if args.json:
    print(json.dumps(report, indent=2))
else:
    print(f"Baseline: {report['base']} → working tree (tracked + nonignored new files)")
    for field, counts in report["totals"].items():
        print(f"\n{field:32} {'Before':>8} {'After':>8} {'Delta':>8}")
        for key in sorted(counts["before"].keys() | counts["after"].keys()):
            old, new = counts["before"].get(key, 0), counts["after"].get(key, 0)
            print(f"{key:32} {old:8,} {new:8,} {new - old:+8,}")
