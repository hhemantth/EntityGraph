#!/usr/bin/env python3
from pathlib import Path
import json

root = Path(__file__).resolve().parents[1]
required = [
    root / "index.html",
    root / "styles.css",
    root / "app.js",
    root / "assets" / "entitygraph-logo.svg",
    root / "assets" / "favicon.svg",
    root / "README.md",
]
missing = [str(path.relative_to(root)) for path in required if not path.exists()]
if missing:
    raise SystemExit(f"Missing required files: {', '.join(missing)}")

html = (root / "index.html").read_text(encoding="utf-8")
js = (root / "app.js").read_text(encoding="utf-8")
readme = (root / "README.md").read_text(encoding="utf-8")

checks = {
    "HTML title": "<title>EntityGraph</title>" in html,
    "Visible brand": "brand-name\">EntityGraph" in html,
    "Logo reference": "assets/entitygraph-logo.svg" in html,
    "Favicon reference": "assets/favicon.svg" in html,
    "Empty startup": "Build an investigation graph" in html,
    "CSV import": "function parseCSV" in js and "importRows" in js,
    "Entity resolution": "mergeSelected" in js and "resolutionMap" in js,
    "Merge undo": "undoMerge" in js,
    "Shortest path": "shortestPath" in js,
    "JSON persistence": "EntityGraph Investigation v2" in js,
    "Consistent product name": all(name in (html + js + readme) for name in ["EntityGraph"]),
}
failed = [name for name, passed in checks.items() if not passed]
if failed:
    raise SystemExit("Failed checks: " + ", ".join(failed))

sample = root / "sample-data" / "device-network-events.csv"
if sample.read_text(encoding="utf-8").count("\n") < 2:
    raise SystemExit("Sample CSV has no event rows")

print(json.dumps({"status": "ok", "checks": len(checks), "required_files": len(required)}, indent=2))
