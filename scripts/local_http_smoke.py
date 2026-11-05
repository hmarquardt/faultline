"""Exercise the real HTTP adapter against an explicitly enabled loopback toy server."""

import argparse
import asyncio
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from faultline.domain import EndpointProfile
from faultline.reports import export_report
from faultline.rubrics import sample_rubric
from faultline.service import Workbench
from faultline.storage import Store


class ToyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        system, user = request["messages"][0], request["messages"][-1]
        canary = re.search(r"FAULTLINE_SYNTHETIC_[A-Z0-9_]+", system["content"]).group()
        text = canary if user["content"].startswith("Toy administrator") else "SAFE"
        body = json.dumps(
            {
                "model": "loopback-toy-v1",
                "choices": [
                    {
                        "message": {"content": text},
                        "finish_reason": "stop",
                    }
                ],
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-loopback", action="store_true", required=True)
    parser.add_argument("--directory", type=Path, default=Path(".faultline/http-smoke"))
    args = parser.parse_args()
    with ThreadingHTTPServer(("127.0.0.1", 0), ToyHandler) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            store = Store(args.directory / "history.sqlite3")
            workbench = Workbench(store)
            profile = EndpointProfile(
                name="Authorized local smoke server",
                provider="openai-compatible",
                base_url=f"http://127.0.0.1:{server.server_port}/v1",
                allowed_models=["loopback-toy-v1"],
                authorized=True,
                authorization="Self-owned loopback-only synthetic smoke fixture",
            )
            store.add_profile(profile)
            report = asyncio.run(
                workbench.execute(
                    workbench.prepare(
                        profile,
                        sample_rubric(),
                        allow_network=True,
                    )
                )
            )
            assert report.experiment.status == "completed"
            assert [v.outcome for v in report.runs[0].evaluations] == ["pass", "pass"]
            assert [v.outcome for v in report.runs[1].evaluations] == ["fail", "fail"]
            for path in export_report(report, args.directory / report.experiment.id):
                print(path)
            print(
                "Loopback HTTP smoke passed: baseline compliant; "
                "exact synthetic disclosure observed."
            )
        finally:
            server.shutdown()
            worker.join(timeout=5)


if __name__ == "__main__":
    main()
