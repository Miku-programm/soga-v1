#!/usr/bin/env python3
"""Run the rebuilt process against a local synthetic panel and stop it cleanly."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import queue
import signal
import socket
import subprocess
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    binary = Path(args.binary).resolve()
    if os.name != "posix":
        raise SystemExit("This runtime acceptance check requires Linux.")
    version = subprocess.check_output([binary, "version"], text=True)
    assert "soga-reconstructed" in version and "not original source" in version
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    requests = []
    class Panel(http.server.BaseHTTPRequestHandler):
        def log_message(self, *unused):
            pass
        def reply(self, value):
            body = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def do_GET(self):
            requests.append(self.path)
            if self.path == "/api/v1/node":
                self.reply({"basic": {}, "config": {"port": port, "stream_type": "tcp"}})
            elif self.path == "/api/v1/users":
                self.reply([{"id": 23, "uuid": "2d15433b-392e-4522-b9cc-4b3a0a2c714f"}])
            else:
                self.reply([])
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            requests.append(self.path)
            self.reply({"code": 0})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Panel)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="soga-process-smoke-") as directory:
            folder = Path(directory)
            config = folder / "soga.conf"
            config.write_text(
                "type=soga-v1\nserver_type=vmess\napi=webapi\nnode_id=1\n"
                f"webapi_url=http://127.0.0.1:{server.server_port}\n"
                "webapi_key=synthetic-only\nlisten=127.0.0.1\n"
                "check_interval=3600\nsubmit_interval=3600\nrandom_interval_range=0\n"
                "log_file_dir=false\nauto_update=false\n"
                f"ip_user_cache_save_dir={folder / 'cache'}\n", encoding="utf-8"
            )
            command = [str(binary), "serve", "-c", str(config), "-state-dir", str(folder / "state")]
            for flag, name in [("-b", "blockList"), ("-w", "whiteList"), ("-d", "dns.yml"), ("-r", "routes.toml")]:
                command += [flag, str(folder / name)]
            # Keep ordinary OS variables but exclude all configuration overrides.
            defaults = json.loads(subprocess.check_output([binary, "defaults"], text=True))
            env = {k: v for k, v in os.environ.items() if k not in defaults and not k.startswith("DNS_")}
            with (folder / "stderr.log").open("w+") as error_log:
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=error_log, text=True, env=env)
                lines = queue.Queue()
                def reader():
                    for line in process.stdout:
                        lines.put(line)
                threading.Thread(target=reader, daemon=True).start()
                try:
                    line = lines.get(timeout=30)
                    assert line.strip() == "started 1 node(s)", line
                    with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
                        connection.sendall(b"invalid-protocol-credentials")
                    process.send_signal(signal.SIGTERM)
                    code = process.wait(timeout=30)
                    error_log.seek(0)
                    logs = error_log.read()
                    assert code == 0, (code, logs)
                    assert "/api/v1/node" in requests and "/api/v1/users" in requests
                    assert "/api/v1/status" in requests, (requests, logs)
                    with socket.socket() as probe:
                        probe.settimeout(1)
                        assert probe.connect_ex(("127.0.0.1", port)) != 0
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
            report = {
                "status": "passed", "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "scope": "rebuilt process: fixture panel startup, listener, unauthenticated connection probe, SIGTERM and final status",
                "panel_requests": requests, "exit_code": code, "original_sample_executed": False,
            }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
