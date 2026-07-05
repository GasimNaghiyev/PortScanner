from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
import socket
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, List, Optional

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover
    tqdm = None


@dataclass
class ScanResult:
    target: str
    port: int
    state: str
    service: str
    response_time: float
    banner: str
    error: Optional[str] = None
    os_hint: Optional[str] = None


async def scan_port(
    target: str,
    port: int,
    timeout: float,
    retries: int,
    rate_limit: float,
    banner: bool,
    service_detection: bool,
    os_detection: bool,
) -> ScanResult:
    last_error: Optional[str] = None
    for attempt in range(retries + 1):
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=timeout
            )
            elapsed = time.perf_counter() - start
            banner_text = ""
            if banner:
                try:
                    writer.write(b"\n")
                    await asyncio.wait_for(writer.drain(), timeout=timeout)
                    banner_text = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=timeout)
                except (asyncio.TimeoutError, ConnectionResetError, asyncio.IncompleteReadError):
                    banner_text = ""
            writer.close()
            await writer.wait_closed()
            service = detect_service(port, service_detection)
            os_hint = infer_os_hint(port) if os_detection else None
            if rate_limit > 0:
                await asyncio.sleep(rate_limit)
            return ScanResult(
                target=target,
                port=port,
                state="open",
                service=service,
                response_time=round(elapsed, 3),
                banner=banner_text.decode(errors="ignore").strip(),
                error=None,
                os_hint=os_hint,
            )
        except (ConnectionRefusedError, TimeoutError, asyncio.TimeoutError, OSError) as exc:
            last_error = str(exc)
            if rate_limit > 0:
                await asyncio.sleep(rate_limit)
            if attempt >= retries:
                break
        except Exception as exc:  # pragma: no cover
            last_error = str(exc)
            if attempt >= retries:
                break
    state = "filtered" if "timed out" in (last_error or "").lower() else "closed"
    return ScanResult(
        target=target,
        port=port,
        state=state,
        service=detect_service(port, service_detection),
        response_time=0.0,
        banner="",
        error=last_error,
        os_hint=infer_os_hint(port) if os_detection else None,
    )


def parse_ports(spec: str) -> List[int]:
    ports: List[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start = int(start_s)
            end = int(end_s)
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def expand_targets(targets: List[str]) -> List[str]:
    expanded: List[str] = []
    for target in targets:
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            expanded.append(target)
            continue
        if net.num_addresses == 1:
            expanded.append(str(net.network_address))
        else:
            expanded.extend(str(host) for host in net.hosts())
    return sorted(set(expanded))


def detect_service(port: int, enabled: bool) -> str:
    if not enabled:
        return "unknown"
    common_services = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        3306: "mysql",
        5432: "postgres",
        6379: "redis",
        8080: "http-alt",
        8443: "https-alt",
    }
    return common_services.get(port, "unknown")


def infer_os_hint(port: int) -> str:
    if port in {22, 23, 80, 443, 3389}:
        return "likely network service"
    if port in {53, 67, 68}:
        return "likely infrastructure service"
    return "unknown"


async def scan_targets(
    targets: List[str],
    ports: List[int],
    timeout: float = 1.0,
    retries: int = 1,
    concurrency: int = 50,
    rate_limit: float = 0.0,
    progress: bool = True,
    banner: bool = True,
    service_detection: bool = True,
    os_detection: bool = False,
) -> List[ScanResult]:
    resolved_targets = expand_targets(targets)
    total = len(resolved_targets) * len(ports)
    results: List[ScanResult] = []
    semaphore = asyncio.Semaphore(concurrency)

    async def worker(target: str, port: int) -> ScanResult:
        async with semaphore:
            if rate_limit > 0:
                await asyncio.sleep(rate_limit)
            return await scan_port(
                target=target,
                port=port,
                timeout=timeout,
                retries=retries,
                rate_limit=rate_limit,
                banner=banner,
                service_detection=service_detection,
                os_detection=os_detection,
            )

    tasks = [asyncio.create_task(worker(target, port)) for target in resolved_targets for port in ports]
    if progress and tqdm is not None:
        with tqdm(total=total, desc="Scanning", unit="port") as pbar:
            for task in asyncio.as_completed(tasks):
                result = await task
                results.append(result)
                pbar.update(1)
    else:
        for task in asyncio.as_completed(tasks):
            result = await task
            results.append(result)
    return sorted(results, key=lambda r: (r.target, r.port))


def summarize(results: List[ScanResult]) -> dict[str, Any]:
    totals = {"total": len(results), "open": 0, "closed": 0, "filtered": 0}
    for item in results:
        if item.state == "open":
            totals["open"] += 1
        elif item.state == "filtered":
            totals["filtered"] += 1
        else:
            totals["closed"] += 1
    return totals


def export_results(results: List[ScanResult], path: str) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.suffix.lower() == ".json":
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump([asdict(result) for result in results], handle, indent=2)
    else:
        with output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(asdict(results[0]).keys()) if results else [])
            writer.writeheader()
            for result in results:
                writer.writerow(asdict(result))


def colorize(state: str, text: str, enabled: bool = True) -> str:
    if not enabled or not sys.stdout.isatty():
        return text
    colors = {
        "open": "\033[92m",
        "closed": "\033[93m",
        "filtered": "\033[95m",
    }
    return f"{colors.get(state, '')}{text}\033[0m"


def print_results(results: List[ScanResult], color_enabled: bool = True) -> None:
    for result in results:
        banner = f" | banner: {result.banner}" if result.banner else ""
        os_hint = f" | os: {result.os_hint}" if result.os_hint else ""
        print(
            colorize(
                result.state,
                f"{result.target}:{result.port} [{result.state}] service={result.service} response={result.response_time:.3f}s{banner}{os_hint}",
                enabled=color_enabled,
            )
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Async Python port scanner")
    parser.add_argument("targets", nargs="+", help="IP addresses, hostnames, or CIDR ranges")
    parser.add_argument("--ports", default="1-1024", help="Port range, e.g. 22,80-82")
    parser.add_argument("--concurrency", type=int, default=100, help="Max concurrent connections")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-port timeout in seconds")
    parser.add_argument("--retries", type=int, default=1, help="Number of retries per port")
    parser.add_argument("--rate-limit", type=float, default=0.0, help="Delay between probes in seconds")
    parser.add_argument("--no-progress", action="store_true", help="Disable progress bar")
    parser.add_argument("--no-banner", action="store_true", help="Disable banner grabbing")
    parser.add_argument("--no-service-detection", action="store_true", help="Disable service name hints")
    parser.add_argument("--os-detection", action="store_true", help="Enable OS detection hints")
    parser.add_argument("--json", help="Export results to a JSON file")
    parser.add_argument("--csv", help="Export results to a CSV file")
    parser.add_argument("--no-color", action="store_true", help="Disable colorized output")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    results = asyncio.run(
        scan_targets(
            targets=args.targets,
            ports=parse_ports(args.ports),
            timeout=args.timeout,
            retries=args.retries,
            concurrency=args.concurrency,
            rate_limit=args.rate_limit,
            progress=not args.no_progress,
            banner=not args.no_banner,
            service_detection=not args.no_service_detection,
            os_detection=args.os_detection,
        )
    )

    print_results(results, color_enabled=not args.no_color)
    print("Summary:", json.dumps(summarize(results), indent=2))

    if args.json:
        export_results(results, args.json)
    if args.csv:
        export_results(results, args.csv)
    return 0


if __name__ == "__main__":
    main()
