<div align="center">

<img src="assets/banner.svg" alt="sbomlite" width="100%">

<p>
  <img alt="License" src="https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge">
  <img alt="Python" src="https://img.shields.io/badge/python-3.8%2B-fbbf24?style=for-the-badge&logo=python&logoColor=white">
  <img alt="Format" src="https://img.shields.io/badge/CycloneDX-1.5-34d399?style=for-the-badge">
  <img alt="Dependencies" src="https://img.shields.io/badge/dependencies-zero-38bdf8?style=for-the-badge">
</p>

**"What is actually inside this app?" Answer it with one command.**

</div>

---

## ✨ Why

Customers, auditors and security tools increasingly ask for an **SBOM** (software bill of materials). `sbomlite` reads the lockfiles you already have and writes a standard [CycloneDX](https://cyclonedx.org) 1.5 JSON file, with a package URL (`purl`) for every component.

## 🚀 Usage

```bash
git clone https://github.com/CyberLoop-dev/sbomlite.git

python sbomlite/sbomlite.py ./my-app -o sbom.json   # write a file
python sbomlite/sbomlite.py ./my-app --summary      # quick counts
python sbomlite/sbomlite.py | jq '.components | length'
```

Summary output:

```text
Sources (2):
  my-app/package-lock.json
  my-app/requirements.txt
npm: 412 components
pypi: 37 components (3 without a pinned version)
```

## 📦 Supported files

| Ecosystem | Files |
|---|---|
| Python | `requirements*.txt`, `Pipfile.lock`, `poetry.lock` (needs Python 3.11+ for TOML) |
| Node | `package-lock.json` (v1, v2, v3), `npm-shrinkwrap.json` |

`node_modules`, virtualenvs and `.git` are skipped.

## ⚖️ Honest limits

- It lists **direct and locked dependencies**, not the dependency graph (no `dependencies` relationships yet).
- Entries in `requirements.txt` without `==` have no version. They are included and marked as unpinned.
- No license or hash data. Use it as a starting inventory, then enrich with a scanner if you need more.

## 📄 License

MIT
