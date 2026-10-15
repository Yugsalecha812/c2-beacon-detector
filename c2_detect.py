#!/usr/bin/env python3
"""
C2 Beacon Detector — statistical detection of command-and-control
beaconing behavior in network connection logs.

Detects periodic, low-jitter connection patterns between a source and
destination, which is a classic indicator of C2 check-in traffic,
regardless of the specific protocol or payload (works even against
encrypted C2 channels, since it never inspects payload content — only
connection timing and volume metadata).
"""

import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone


class Connection:
    __slots__ = ("timestamp", "src_ip", "dst_ip", "dst_port", "duration", "bytes_sent")

    def __init__(self, timestamp, src_ip, dst_ip, dst_port, duration=0.0, bytes_sent=0):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.duration = duration
        self.bytes_sent = bytes_sent


def parse_generic_csv(file_path):
    """
    Expects columns: timestamp,src_ip,dst_ip,dst_port,duration,bytes_sent
    timestamp may be a unix epoch (int/float) or ISO 8601 string.
    """
    connections = []
    with open(file_path, newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
           
           
            ts_raw = row["timestamp"].strip()
            try:
                ts = float(ts_raw)
            except ValueError:
                try:
                    ts = datetime.fromisoformat(ts_raw).timestamp()
                except ValueError as exc:
                    raise ValueError(
                        f"Invalid timestamp at CSV row {reader.line_num}: "
                        f"{ts_raw!r}"
                    ) from exc

                except ValueError as exc:
                    raise ValueError(
                        f"Invalid timestamp at CSV row {reader.line_num}: "
                        f"{ts_raw!r}"
                    ) from exc

            connections.append(Connection(
                timestamp=ts,
                src_ip=row["src_ip"].strip(),
                dst_ip=row["dst_ip"].strip(),
                dst_port=row.get("dst_port", "").strip(),
                duration=float(row.get("duration", 0) or 0),
                bytes_sent=int(float(row.get("bytes_sent", 0) or 0)),
            ))
    return connections


def parse_zeek_conn_log(file_path):
    """
    Parses a Zeek/Bro conn.log (tab-separated, with a #fields header line
    declaring column order). Only the fields this tool needs are extracted;
    everything else in the log is ignored.
    """
    connections = []
    fields = None

    with open(file_path, encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            if fields is None:
                continue

            values = line.split("\t")
            row = dict(zip(fields, values))

            try:
                ts = float(row.get("ts", 0))
                orig_bytes = row.get("orig_bytes", "0")
                orig_bytes = int(orig_bytes) if orig_bytes not in ("-", "") else 0
                duration = row.get("duration", "0")
                duration = float(duration) if duration not in ("-", "") else 0.0

                connections.append(Connection(
                    timestamp=ts,
                    src_ip=row.get("id.orig_h", "unknown"),
                    dst_ip=row.get("id.resp_h", "unknown"),
                    dst_port=row.get("id.resp_p", ""),
                    duration=duration,
                    bytes_sent=orig_bytes,
                ))
            except (ValueError, KeyError):
                continue

    return connections


class BeaconDetector:
    """
    Groups connections by (src_ip, dst_ip, dst_port) and scores each group
    for beaconing behavior based on the regularity of inter-arrival times.

    The core metric is the coefficient of variation (CoV = stddev / mean)
    of the intervals between consecutive connections in a group. Human or
    bursty application traffic tends to have irregular timing (high CoV).
    Malware beacons calling home on a fixed interval — even with jitter —
    tend to have low CoV, since jitter is usually a small percentage of
    the base interval rather than fully random timing.
    """

    def __init__(self, min_connections=5, cov_threshold=0.30):
        self.min_connections = min_connections
        self.cov_threshold = cov_threshold

    def group_connections(self, connections):
        groups = defaultdict(list)
        for conn in connections:
            key = (conn.src_ip, conn.dst_ip, conn.dst_port)
            groups[key].append(conn)
        for key in groups:
            groups[key].sort(key=lambda c: c.timestamp)
        return groups

    def score_group(self, conns):
        if len(conns) < self.min_connections:
            return None

        timestamps = [c.timestamp for c in conns]
        intervals = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]

        # Guard against a burst of near-simultaneous connections producing
        # a degenerate (near-zero) mean interval, which would make CoV
        # meaningless.
        mean_interval = statistics.mean(intervals)
        if mean_interval < 1.0:
            return None

        stdev_interval = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        cov = stdev_interval / mean_interval if mean_interval > 0 else float("inf")

        byte_counts = [c.bytes_sent for c in conns]
        mean_bytes = statistics.mean(byte_counts) if byte_counts else 0
        stdev_bytes = statistics.pstdev(byte_counts) if len(byte_counts) > 1 else 0.0
        byte_cov = (stdev_bytes / mean_bytes) if mean_bytes > 0 else 0.0

        is_beacon = cov <= self.cov_threshold

        return {
            "connection_count": len(conns),
            "mean_interval_seconds": round(mean_interval, 2),
            "interval_stdev_seconds": round(stdev_interval, 2),
            "interval_coefficient_of_variation": round(cov, 4),
            "mean_bytes_sent": round(mean_bytes, 1),
            "byte_coefficient_of_variation": round(byte_cov, 4),
            "is_beacon": is_beacon,
            "confidence": self._confidence_label(cov, byte_cov, len(conns)),
        }

    def _confidence_label(self, cov, byte_cov, count):
        if cov > self.cov_threshold:
            return "NONE"
        # Tighter timing regularity + consistent payload size + more
        # samples all raise confidence this is scripted/automated traffic
        # rather than a coincidentally regular human workflow.
        score = 0
        if cov <= 0.10:
            score += 2
        elif cov <= 0.20:
            score += 1
        if byte_cov <= 0.15:
            score += 1
        if count >= 20:
            score += 1

        if score >= 3:
            return "HIGH"
        elif score >= 1:
            return "MEDIUM"
        return "LOW"

    def analyze(self, connections):
        groups = self.group_connections(connections)
        results = []

        for (src_ip, dst_ip, dst_port), conns in groups.items():
            result = self.score_group(conns)
            if result is None:
                continue
            if result["is_beacon"]:
                result.update({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "first_seen": datetime.fromtimestamp(conns[0].timestamp, tz=timezone.utc).isoformat(),
                    "last_seen": datetime.fromtimestamp(conns[-1].timestamp, tz=timezone.utc).isoformat(),
                })
                results.append(result)

        results.sort(key=lambda r: r["interval_coefficient_of_variation"])
        return results


def print_report(results, total_connections, total_groups):
    print("\n" + "=" * 70)
    print("            C2 BEACON DETECTION REPORT")
    print("=" * 70)
    print(f"Total connections analyzed : {total_connections}")
    print(f"Unique src/dst/port groups : {total_groups}")
    print(f"Suspected beacons found    : {len(results)}")
    print("-" * 70)

    if not results:
        print("No beaconing patterns detected above the configured threshold.")
    else:
        for r in results:
            print(
                f"[{r['confidence']:<6}] {r['src_ip']} -> {r['dst_ip']}:{r['dst_port']}  "
                f"({r['connection_count']} conns, interval={r['mean_interval_seconds']}s "
                f"+/-{r['interval_coefficient_of_variation']*100:.1f}%)"
            )
    print("=" * 70 + "\n")


def export_json(results, output_file):
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump({
            "generated": datetime.now(timezone.utc).isoformat(),
            "beacon_count": len(results),
            "beacons": results,
        }, f, indent=2)
    print(f"[+] Results exported to {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Statistical C2 beacon detector for connection logs")
    parser.add_argument("-f", "--file", required=True, help="Path to connection log (CSV or Zeek conn.log)")
    parser.add_argument("--format", choices=["csv", "zeek"], default="csv", help="Input log format (default: csv)")
    parser.add_argument("--min-connections", type=int, default=5, help="Minimum connections per group to consider (default: 5)")
    parser.add_argument("--cov-threshold", type=float, default=0.30, help="Max coefficient of variation to flag as beaconing (default: 0.30)")
    parser.add_argument("-o", "--output", help="Save results as JSON")

    args = parser.parse_args()

    if args.format == "zeek":
        connections = parse_zeek_conn_log(args.file)
    else:
        connections = parse_generic_csv(args.file)

    if not connections:
        print("[!] No connections parsed from input file.", file=sys.stderr)
        sys.exit(1)

    detector = BeaconDetector(min_connections=args.min_connections, cov_threshold=args.cov_threshold)
    groups = detector.group_connections(connections)
    results = detector.analyze(connections)

    print_report(results, len(connections), len(groups))

    if args.output:
        export_json(results, args.output)


if __name__ == "__main__":
    main()
