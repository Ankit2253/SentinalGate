"""Parse nftables kernel logs and detect horizontal/vertical scan behaviour."""

from __future__ import annotations

import re
import subprocess
import time
from collections import defaultdict, deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from sentinelgate.models import Event
from sentinelgate.service import FirewallService

TOKEN_PATTERN = re.compile(r"\b([A-Z][A-Z0-9_]*)=([^\s]+)")
PREFIX_PATTERN = re.compile(r"\b(SG_[A-Z0-9_]+)\b")
HIGH_INTEREST_PORTS = {22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379}


def parse_nft_log(line: str) -> Event | None:
    prefix_match = PREFIX_PATTERN.search(line)
    if not prefix_match:
        return None
    values = {key: value for key, value in TOKEN_PATTERN.findall(line)}
    source = values.get("SRC")
    destination = values.get("DST")
    if not source:
        return None
    try:
        destination_port = int(values["DPT"]) if "DPT" in values else None
    except ValueError:
        destination_port = None
    prefix = prefix_match.group(1)
    severity = "high" if "BLOCKLIST" in prefix else "low"
    if destination_port in HIGH_INTEREST_PORTS:
        severity = "medium" if severity == "low" else severity
    return Event(
        event_type="firewall_drop",
        severity=severity,
        action="blocked",
        source_ip=source,
        destination_ip=destination,
        destination_port=destination_port,
        protocol=values.get("PROTO", "").lower() or None,
        rule_id=prefix.removeprefix("SG_RULE_") if prefix.startswith("SG_RULE_") else None,
        raw=line.strip()[:4000],
        details={"prefix": prefix, "input_interface": values.get("IN")},
    )


@dataclass(slots=True)
class Detection:
    source_ip: str
    count: int
    unique_ports: int


class ScanDetector:
    def __init__(self, threshold: int, window_seconds: int):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._activity: dict[str, deque[tuple[float, int | None]]] = defaultdict(deque)

    def observe(self, event: Event, now: float | None = None) -> Detection | None:
        if not event.source_ip:
            return None
        current = time.monotonic() if now is None else now
        queue = self._activity[event.source_ip]
        queue.append((current, event.destination_port))
        cutoff = current - self.window_seconds
        while queue and queue[0][0] < cutoff:
            queue.popleft()
        ports = {port for _, port in queue if port is not None}
        minimum_unique = min(5, self.threshold)
        if len(queue) >= self.threshold and len(ports) >= minimum_unique:
            detection = Detection(event.source_ip, len(queue), len(ports))
            queue.clear()
            return detection
        return None


class FirewallMonitor:
    def __init__(self, service: FirewallService):
        self.service = service
        self.detector = ScanDetector(
            service.config.firewall.scan_threshold,
            service.config.firewall.scan_window_seconds,
        )

    def process(self, lines: Iterable[str]) -> int:
        processed = 0
        for line in lines:
            event = parse_nft_log(line)
            if not event:
                continue
            self.service.database.add_event(event)
            processed += 1
            detection = self.detector.observe(event)
            if detection and self.service.config.firewall.auto_block:
                try:
                    self.service.ban(
                        detection.source_ip,
                        f"Port scan: {detection.count} attempts across "
                        f"{detection.unique_ports} ports",
                    )
                except ValueError:
                    self.service.database.add_event(
                        Event(
                            event_type="auto_block_suppressed",
                            severity="info",
                            action="protected",
                            source_ip=detection.source_ip,
                            details={"reason": "Protected management address"},
                        )
                    )
        return processed


def journal_lines() -> Iterator[str]:
    process = subprocess.Popen(
        ["journalctl", "-k", "-f", "-o", "cat", "--no-pager"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.stdout is None:
        raise RuntimeError("Unable to read journalctl output")
    try:
        yield from process.stdout
    finally:
        process.terminate()

