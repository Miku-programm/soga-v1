#!/usr/bin/env python3
"""Smoke-test the rebuilt CLI, never the original analyzed binary."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", help="Path to this project's compiled binary")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    binary = Path(args.binary).resolve()
    fixture = root / "examples" / "soga.conf"
    before = hashlib.sha256(fixture.read_bytes()).hexdigest()
    records = []

    def run(arguments, expected=0):
        result = subprocess.run(
            [str(binary), *arguments], cwd=root, capture_output=True,
            text=True, encoding="utf-8", timeout=20,
        )
        records.append({
            "arguments": arguments, "exit_code": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr,
        })
        assert result.returncode == expected, records[-1]
        return result.stdout

    version = run(["version"])
    assert "2.17.0" in version and "not original source" in version
    assert len(json.loads(run(["defaults"]))) == 157
    inspect = json.loads(run(["inspect", "-c", "examples/soga.conf", "-node_id", "12"]))
    assert inspect["normalized_server_type"] == "v2ray"
    assert inspect["legacy_api_key_selected"] is False
    assert inspect["values"]["node_id"] == "12"
    assert inspect["values"]["webapi_key"] == "[REDACTED]"
    assert inspect["values"]["ban_private_ip"] == "false"
    empty = json.loads(run(["inspect", "-c", "examples/soga.conf", "-server_type", ""]))
    assert empty["normalized_server_type"] == ""
    rules = json.loads(run(["list", "-file", "examples/blockList", "-forbidden-ports", "25,465"]))
    assert rules == ["domain:example.test", "port:25", "port:25", "port:465"], rules
    run(["serve", "-c", "examples/nonexistent-fixture.conf"], expected=1)
    run(["instance"])
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == before
    report = {
        "status": "passed",
        "scope": "rebuilt CLI smoke only; protocol and panel integration are tested separately; no original soga execution",
        "platform": os.name,
        "binary_name": binary.name,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "fixture_unchanged": True,
        "invocations": records,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "binary": binary.name, "invocations": len(records)}))


if __name__ == "__main__":
    main()
