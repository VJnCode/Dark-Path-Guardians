"""Package the Chrome extension into an installable folder and a .zip.

Usage:
    python scripts/build_extension.py            # -> dist/dark-path-guardians/ and dist/dark-path-guardians-<version>.zip

Install:
    - Load unpacked: chrome://extensions -> Developer mode -> Load unpacked -> dist/dark-path-guardians/
    - Chrome Web Store / Edge Add-ons: upload the .zip
"""
import json
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "extension"
DIST = ROOT / "dist"
NAME = "dark-path-guardians"
# Only files the extension needs at runtime are shipped.
SHIP_SUFFIXES = {".json", ".js", ".html", ".css", ".png"}


def referenced_files(manifest: dict) -> set[str]:
    """Files the manifest points to; each must exist or Chrome refuses to load the extension."""
    refs = {manifest["background"]["service_worker"], manifest["action"]["default_popup"],
            manifest["action"]["default_icon"]}
    refs.update(manifest.get("icons", {}).values())
    return refs


def main() -> int:
    manifest = json.loads((SRC / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("manifest_version") != 3:
        print("error: manifest_version must be 3")
        return 1
    missing = [f for f in referenced_files(manifest) if not (SRC / f).is_file()]
    # Pages and scripts loaded by name from the code, not the manifest.
    missing += [f for f in ("content.js", "sandbox.html", "sandbox.js") if not (SRC / f).is_file()]
    if missing:
        print("error: missing files:", ", ".join(missing))
        return 1

    files = sorted(p for p in SRC.rglob("*") if p.is_file() and p.suffix in SHIP_SUFFIXES)

    out_dir = DIST / NAME
    if out_dir.exists():
        shutil.rmtree(out_dir)
    for p in files:
        dest = out_dir / p.relative_to(SRC)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dest)

    zip_path = DIST / f"{NAME}-{manifest['version']}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in files:
            # manifest.json must sit at the zip root for store uploads.
            z.write(p, p.relative_to(SRC).as_posix())

    print(f"Built {manifest['name']} v{manifest['version']} ({len(files)} files)")
    print(f"  unpacked: {out_dir}")
    print(f"  zip:      {zip_path}")
    print("Load it: chrome://extensions -> Developer mode -> Load unpacked -> the unpacked folder above")
    return 0


if __name__ == "__main__":
    sys.exit(main())
