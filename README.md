# Async Python Port Scanner

A modern, cross-platform port scanner built with Python 3.9+ standard libraries.

## Features

- Async/concurrent scanning with `asyncio`
- Multiple targets and CIDR support
- Custom port ranges
- Open/closed/filtered port detection
- Service hints and banner grabbing
- Response times and summary statistics
- JSON/CSV export
- Optional progress bar
- Timeout and retry handling
- Colorized CLI output

## Usage

Run against one or more hosts:

```bash
python port_scanner.py 127.0.0.1 --ports "22,80,443" --timeout 0.5 --retries 1 --concurrency 50
```

Scan a CIDR range:

```bash
python port_scanner.py 192.168.1.0/24 --ports "1-1024" --rate-limit 0.05 --json results.json --csv results.csv
```

## Notes

- Progress bar support improves with `tqdm` if installed.
- The scanner intentionally avoids `nmap` and other third-party tools.
