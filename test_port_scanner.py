import asyncio
import socketserver
import threading
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from port_scanner import parse_ports, expand_targets, scan_targets


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(1024)
        self.request.sendall(b"banner-test\n")


class PortScannerTests(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(parse_ports("22,80-82"), [22, 80, 81, 82])

    def test_expand_targets(self):
        targets = expand_targets(["127.0.0.1", "127.0.0.1/32"])
        self.assertEqual(targets, ["127.0.0.1"])

    def test_scan_targets_finds_open_and_closed_ports(self):
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            results = asyncio.run(
                scan_targets(
                    targets=["127.0.0.1"],
                    ports=[port, 65534],
                    timeout=0.5,
                    retries=0,
                    concurrency=10,
                    rate_limit=0.0,
                    progress=False,
                    banner=True,
                    service_detection=True,
                    os_detection=False,
                )
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        open_results = [r for r in results if r.state == "open"]
        self.assertEqual(len(open_results), 1)
        self.assertEqual(open_results[0].port, port)
        self.assertIn(open_results[0].service, {"http", "unknown"})


if __name__ == "__main__":
    unittest.main()
