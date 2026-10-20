#!/usr/bin/env python3
"""Rebuild the project's legal-file index without rewriting upstream files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

SCOPES = (
    "vendor", "third_party", "certificates/bundled", "geodata/bundled",
    "testdata/ssr-reference", "proxy",
)
SKIP_DIRS = {".git", "__pycache__", ".cache", "node_modules"}
LEGAL = re.compile(r"(^|[-_.])(licen[cs]e[s]?|notice|copying|copyright|patents|authors|contributors|attribution)([-_.]|$)", re.I)
PROVENANCE = {"SOURCE.json", "PROVENANCE.txt", "PROVENANCE.json"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def is_legal(path):
    return bool(LEGAL.search(path.name)) and path.suffix.lower() not in {".go", ".py", ".sh", ".c", ".h"}


def files_below(root):
    if not root.is_dir():
        return
    with os.scandir(root) as entries:
        entries = sorted(entries, key=lambda e: e.name)
    for entry in entries:
        if entry.is_symlink():
            continue
        if entry.is_dir(follow_symlinks=False):
            if entry.name not in SKIP_DIRS:
                yield from files_below(Path(entry.path))
        elif entry.is_file(follow_symlinks=False):
            yield Path(entry.path)


def parse_modules(path):
    modules = []
    current = None
    for line in path.read_text().splitlines():
        if line.startswith("# "):
            parts = line[2:].split()
            if len(parts) < 2 or parts[1] == "=>":
                current = None
                continue
            current = {"module": parts[0], "version": parts[1], "packages": []}
            if "=>" in parts:
                current["replacement"] = " ".join(parts[parts.index("=>") + 1:])
            modules.append(current)
        elif current is not None and line and not line.startswith("#"):
            current["packages"].append(line)
    return modules


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--goroot", type=Path, help="Optional Go source tree; copies its legal notices separately.")
    args = parser.parse_args()
    project = args.project.resolve()
    destination = project / "LICENSES"
    destination.mkdir(exist_ok=True)
    records = []
    generated = set()

    def copy(path, relative, origin, kind):
        data = path.read_bytes()
        out = destination / relative
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        generated.add(relative)
        records.append({
            "path": relative, "source": origin, "kind": kind,
            "bytes": len(data), "sha256": digest(data),
        })

    for scope in SCOPES:
        source = project / scope
        if not source.is_dir():
            raise SystemExit("Required source directory is missing: " + str(source))
        for path in files_below(source):
            relative = path.relative_to(project).as_posix()
            if is_legal(path):
                copy(path, relative, relative, "legal-text")
            elif path.name in PROVENANCE:
                copy(path, relative, relative, "provenance")
    for name in ("geoip-README.md", "domain-list-community-README.md"):
        path = project / "geodata/bundled" / name
        if path.is_file():
            rel = path.relative_to(project).as_posix()
            copy(path, rel, rel, "data-attribution-context")

    modules_file = project / "vendor/modules.txt"
    copy(modules_file, "vendor/modules.txt", "vendor/modules.txt", "module-index")
    modules = parse_modules(modules_file)
    # Require a license in the module root or an ancestor, not merely a nested
    # subcomponent whose license might have a different scope.
    legal = [r["path"] for r in records if r["kind"] == "legal-text"]
    for module in modules:
        root = Path("vendor") / module["module"]
        ancestors = {root, *root.parents}
        ancestors.discard(Path("vendor"))
        ancestors.discard(Path("."))
        module["root_legal_files"] = sorted(p for p in legal if Path(p).parent in ancestors)
        module["nested_legal_files"] = sorted(p for p in legal if p.startswith(root.as_posix() + "/") and p not in module["root_legal_files"])
        module["status"] = "root-legal-file-present" if module["root_legal_files"] else ("no-vendored-packages" if not module["packages"] else "missing-root-legal-file")

    go_metadata = None
    if args.goroot:
        goroot = args.goroot.resolve()
        version = (goroot / "VERSION").read_text().splitlines()[0]
        prefix = "go-standard-library/" + version
        # Include standard-library legal files and its bundled dependencies,
        # but exclude compiler tools and test fixtures that are not in our binary.
        candidates = [goroot / "LICENSE", goroot / "PATENTS"]
        candidates.extend(p for p in files_below(goroot / "src/vendor") if is_legal(p))
        candidates.extend(p for p in files_below(goroot / "src/crypto/internal/boring") if is_legal(p))
        for path in sorted(set(candidates)):
            if path.is_file():
                relative = path.relative_to(goroot).as_posix()
                copy(path, prefix + "/" + relative, "Go " + version + "/" + relative, "go-standard-library-legal-text")
        go_metadata = {"version": version, "license_directory": prefix, "upstream": "https://go.dev/", "note": "Go standard library and bundled legal notices; this is not a copy of the Go toolchain. Some included subcomponents may be inactive in the selected build."}
    else:
        # Existing external Go notices remain byte-for-byte, allowing a source
        # recipient to refresh the project index without this exact toolchain.
        go_root = destination / "go-standard-library"
        if go_root.is_dir():
            for path in files_below(go_root):
                relative = path.relative_to(destination).as_posix()
                data = path.read_bytes()
                generated.add(relative)
                records.append({"path": relative, "source": "retained " + relative, "kind": "go-standard-library-legal-text", "bytes": len(data), "sha256": digest(data)})

    # Remove only generated mirror files that disappeared from their source.
    # Never touch collection scripts or manually maintained README files.
    for scope in (*SCOPES, "go-standard-library"):
        for path in files_below(destination / scope):
            if path.relative_to(destination).as_posix() not in generated:
                path.unlink()
    records.sort(key=lambda r: r["path"])
    missing = [m["module"] for m in modules if m["status"] == "missing-root-legal-file"]
    manifest = {
        "schema": 1,
        "description": "Byte-preserving third-party legal files and source metadata, mirrored by original source path. Presence checks are an inventory, not a legal compatibility opinion.",
        "source_scopes": list(SCOPES),
        "go_mod_sha256": digest((project / "go.mod").read_bytes()),
        "go_sum_sha256": digest((project / "go.sum").read_bytes()),
        "vendor_modules_sha256": digest(modules_file.read_bytes()),
        "go_standard_library": go_metadata,
        "counts": {
            "files": len(records),
            "legal_texts": sum(r["kind"] == "legal-text" for r in records),
            "vendored_modules": len(modules),
            "modules_with_packages": sum(bool(m["packages"]) for m in modules),
            "modules_missing_root_legal_file": len(missing),
        },
        "files": records,
        "modules": modules,
        "missing_root_legal_files": missing,
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    rows = ["module\tversion\treplacement\tpackages\tstatus\troot_legal_files\tnested_legal_files"]
    for module in modules:
        rows.append("\t".join((module["module"], module["version"], module.get("replacement", ""), str(len(module["packages"])), module["status"], ";".join(module["root_legal_files"]), ";".join(module["nested_legal_files"]))))
    (destination / "MODULES.tsv").write_text("\n".join(rows) + "\n")
    (destination / "SHA256SUMS").write_text("".join(r["sha256"] + "  " + r["path"] + "\n" for r in records))
    print(json.dumps({"counts": manifest["counts"], "missing_root_legal_files": missing}, ensure_ascii=False))
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
