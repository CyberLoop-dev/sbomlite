#!/usr/bin/env python3
"""sbomlite: generate a CycloneDX SBOM from your lockfiles.

Reads requirements*.txt, Pipfile.lock, poetry.lock, package-lock.json and npm-shrinkwrap.json.

    python sbomlite.py                    # scan the current folder, print JSON
    python sbomlite.py ./my-app -o sbom.json
    python sbomlite.py --summary          # human-readable counts instead of JSON
"""
import argparse
import datetime
import json
import os
import re
import sys
import uuid
from pathlib import Path
from urllib.parse import quote

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", ".tox"}
REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([^\s;,#]+)?")


def pypi_name(n):
    return re.sub(r"[-_.]+", "-", n).lower()


def purl(eco, name, version):
    if eco == "pypi":
        base = f"pkg:pypi/{pypi_name(name)}"
    else:
        base = "pkg:npm/" + "/".join(quote(p, safe="") for p in name.split("/", 1))
    return f"{base}@{version}" if version else base


def parse_requirements(path):
    out = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.split(" #")[0].strip()
        if not line or line.startswith(("-", "#")) or "://" in line:
            continue
        m = REQ_RE.match(line)
        if m:
            name, op, ver = m.group(1), m.group(3), m.group(4)
            out.append(("pypi", name, ver if op == "==" else None))
    return out


def parse_pipfile_lock(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            ver = (info.get("version") or "").lstrip("=") or None
            out.append(("pypi", name, ver))
    return out


def parse_poetry_lock(path):
    try:
        import tomllib
    except ImportError:
        print(f"sbomlite: skipping {path} (needs Python 3.11+ to read TOML)", file=sys.stderr)
        return []
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return [("pypi", p["name"], p.get("version")) for p in data.get("package", [])]


def parse_npm_lock(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    if data.get("packages"):
        for p, info in data["packages"].items():
            if not p:
                continue
            name = info.get("name") or p.split("node_modules/")[-1]
            out.append(("npm", name, info.get("version")))
    else:
        def walk(deps):
            for name, info in (deps or {}).items():
                out.append(("npm", name, info.get("version")))
                walk(info.get("dependencies"))
        walk(data.get("dependencies"))
    return out


def find_files(root):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            yield Path(dirpath) / f


def scan(root):
    found, sources = {}, []
    for p in find_files(root):
        n = p.name.lower()
        try:
            if re.fullmatch(r"requirements.*\.txt", n):
                items = parse_requirements(p)
            elif n == "pipfile.lock":
                items = parse_pipfile_lock(p)
            elif n == "poetry.lock":
                items = parse_poetry_lock(p)
            elif n in ("package-lock.json", "npm-shrinkwrap.json"):
                items = parse_npm_lock(p)
            else:
                continue
        except (OSError, ValueError, KeyError) as e:
            print(f"sbomlite: could not read {p}: {e}", file=sys.stderr)
            continue
        sources.append(str(p))
        for eco, name, ver in items:
            found[(eco, name.lower() if eco == "pypi" else name, ver)] = (eco, name, ver)
    return sorted(found.values(), key=lambda x: (x[0], x[1].lower(), x[2] or "")), sources


def build_bom(root, comps, sources):
    components = []
    for eco, name, ver in comps:
        ref = purl(eco, name, ver)
        c = {"type": "library", "bom-ref": ref, "name": name, "purl": ref}
        if ver:
            c["version"] = ver
        else:
            c["properties"] = [{"name": "sbomlite:note", "value": "version not pinned in source"}]
        components.append(c)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "sbomlite"}]},
            "component": {"type": "application", "name": Path(root).resolve().name},
        },
        "components": components,
    }


def main():
    ap = argparse.ArgumentParser(description="Generate a CycloneDX SBOM from lockfiles.")
    ap.add_argument("path", nargs="?", default=".", help="project folder (default: .)")
    ap.add_argument("-o", "--output", help="write JSON to this file")
    ap.add_argument("--summary", action="store_true", help="print a short summary instead of JSON")
    a = ap.parse_args()

    if not Path(a.path).is_dir():
        sys.exit(f"sbomlite: not a folder: {a.path}")
    comps, sources = scan(a.path)
    if not comps:
        sys.exit("sbomlite: no supported dependency files found")

    if a.summary:
        eco = {}
        for e, _, v in comps:
            d = eco.setdefault(e, [0, 0])
            d[0] += 1
            d[1] += 0 if v else 1
        print(f"Sources ({len(sources)}):")
        for s in sources:
            print("  " + s)
        for e, (n, unpinned) in eco.items():
            print(f"{e}: {n} components" + (f" ({unpinned} without a pinned version)" if unpinned else ""))
        return
    bom = build_bom(a.path, comps, sources)
    text = json.dumps(bom, indent=2)
    if a.output:
        Path(a.output).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {a.output} ({len(comps)} components)", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
