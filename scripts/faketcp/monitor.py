#!/usr/bin/env python3
"""Read Linux /proc metrics; stop only explicitly registered test processes."""

import argparse
import datetime
import json
import os
from pathlib import Path
import select
import signal
import sys
import time


RUN_ENV = "HY2_VALIDATION_RUN_ID"
MIB = 1024 * 1024
TICKS = os.sysconf("SC_CLK_TCK")
STOP_SIGNAL = None
OUTPUT_FAILED = False


def emit(event, **fields):
    global OUTPUT_FAILED
    try:
        print(json.dumps({"event": event, "time_utc": datetime.datetime.now(
            datetime.timezone.utc).isoformat(), **fields}, separators=(",", ":")), flush=True)
    except (OSError, ValueError):
        # Losing the log sink must not prevent the remaining registered PIDs
        # from being stopped in finally.
        OUTPUT_FAILED = True


def proc_stat(pid):
    # comm can contain spaces and parentheses; fields after its last ')' are fixed.
    text = Path(f"/proc/{pid}/stat").read_text()
    fields = text[text.rfind(")") + 2:].split()
    return {"start_ticks": int(fields[19]), "cpu_ticks": int(fields[11]) + int(fields[12])}


def host_snapshot():
    fields = Path("/proc/stat").read_text().splitlines()[0].split()
    ticks = [int(v) for v in fields[1:9]]  # guest times are already in user/nice.
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        name, value = line.split(":", 1)
        if name in ("MemTotal", "MemAvailable"):
            memory[name] = int(value.split()[0]) * 1024
    return {"total_ticks": sum(ticks), "idle_ticks": ticks[3],
            "iowait_ticks": ticks[4], "irq_ticks": ticks[5], "softirq_ticks": ticks[6],
            "steal_ticks": ticks[7],
            "mem_total_bytes": memory["MemTotal"],
            "mem_available_bytes": memory["MemAvailable"]}


def host_metrics(current, previous):
    result = {k: v for k, v in current.items() if k.startswith("mem_")}
    result.update(cpu_percent=None, iowait_percent=None, irq_percent=None,
                  softirq_percent=None, steal_percent=None)
    if previous is not None:
        total = current["total_ticks"] - previous["total_ticks"]
        if total > 0:
            idle = current["idle_ticks"] - previous["idle_ticks"]
            iowait = max(0, current["iowait_ticks"] - previous["iowait_ticks"])
            steal = max(0, current["steal_ticks"] - previous["steal_ticks"])
            irq = max(0, current["irq_ticks"] - previous["irq_ticks"])
            softirq = max(0, current["softirq_ticks"] - previous["softirq_ticks"])
            result.update(cpu_percent=round(100 * (total - idle - iowait) / total, 2),
                          iowait_percent=round(100 * iowait / total, 2),
                          irq_percent=round(100 * irq / total, 2),
                          softirq_percent=round(100 * softirq / total, 2),
                          steal_percent=round(100 * steal / total, 2))
    return result


class GuardedProcess:
    def __init__(self, pid, run_id, work_dir, observe_only):
        self.pid, self.run_id, self.work_dir = pid, run_id, work_dir
        self.start_ticks = proc_stat(pid)["start_ticks"]
        self.pidfd = None
        self.previous = None
        self.verify_identity()
        if not observe_only:
            if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
                raise RuntimeError("termination requires Python pidfd APIs; use observation only or a newer Python")
            self.pidfd = os.pidfd_open(pid, 0)
            try:
                self.verify_identity()
            except Exception:
                os.close(self.pidfd)
                self.pidfd = None
                raise

    def verify_identity(self):
        if proc_stat(self.pid)["start_ticks"] != self.start_ticks:
            raise RuntimeError(f"PID {self.pid} no longer identifies the registered process")
        expected = f"{RUN_ENV}={self.run_id}".encode()
        environment = Path(f"/proc/{self.pid}/environ").read_bytes().split(b"\0")
        if expected not in environment:
            raise RuntimeError(f"PID {self.pid} lacks the exact run marker")
        exe = Path(os.readlink(f"/proc/{self.pid}/exe").removesuffix(" (deleted)")).resolve()
        cwd = Path(os.readlink(f"/proc/{self.pid}/cwd")).resolve()
        if self.work_dir not in exe.parents or not (cwd == self.work_dir or self.work_dir in cwd.parents):
            raise RuntimeError(f"PID {self.pid} executable/cwd is outside the approved test directory")
        self.executable = str(exe)

    def exited(self):
        if self.pidfd is not None:
            return bool(select.select([self.pidfd], [], [], 0)[0])
        try:
            return proc_stat(self.pid)["start_ticks"] != self.start_ticks
        except FileNotFoundError:
            return True

    def sample(self, now):
        if self.exited():
            return None
        try:
            stat = proc_stat(self.pid)
            if stat["start_ticks"] != self.start_ticks:
                raise RuntimeError(f"PID {self.pid} identity changed")
            status = {}
            for line in Path(f"/proc/{self.pid}/status").read_text().splitlines():
                name, value = line.split(":", 1)
                if name in ("VmRSS", "Threads"):
                    status[name] = int(value.split()[0])
            result = {"pid": self.pid, "start_ticks": self.start_ticks,
                      "rss_bytes": status.get("VmRSS", 0) * 1024,
                      "threads": status["Threads"],
                      "fds": len(os.listdir(f"/proc/{self.pid}/fd")), "cpu_percent": None}
        except (FileNotFoundError, ProcessLookupError):
            return None
        if self.previous is not None:
            elapsed = now - self.previous[0]
            result["cpu_percent"] = round(100 * (stat["cpu_ticks"] - self.previous[1]) / TICKS / elapsed, 2)
        self.previous = (now, stat["cpu_ticks"])
        return result

    def send_signal(self, sig):
        if self.pidfd is None or self.exited():
            return
        try:
            self.verify_identity()
            signal.pidfd_send_signal(self.pidfd, sig, None, 0)
            emit("signal", pid=self.pid, start_ticks=self.start_ticks, signal=signal.Signals(sig).name)
        except (FileNotFoundError, ProcessLookupError):
            pass
        except Exception as exc:
            emit("signal_refused", pid=self.pid, error=str(exc))

    def close(self):
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None


def stop_processes(processes, grace):
    for process in processes:
        process.send_signal(signal.SIGTERM)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline and any(not p.exited() for p in processes):
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    for process in processes:
        process.send_signal(signal.SIGKILL)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("baseline", "watch"))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--pid", type=int, action="append", default=[])
    parser.add_argument("--work-dir", type=Path, default=Path("/root/tmp/hy2"))
    parser.add_argument("--duration", type=float, default=120, help="hard wall-clock limit in seconds")
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--max-host-cpu", type=float, default=70, help="whole-host percent, 100 = all CPUs")
    parser.add_argument("--max-test-cpu", type=float, default=40, help="sum of registered processes, 100 = one core")
    parser.add_argument("--cpu-breach-samples", type=int, default=3)
    parser.add_argument("--min-mem-available-mib", type=float, default=256)
    parser.add_argument("--max-test-rss-mib", type=float, default=160)
    parser.add_argument("--max-fds", type=int, default=256, help="per registered process")
    parser.add_argument("--max-threads", type=int, default=32, help="per registered process")
    parser.add_argument("--term-grace", type=float, default=2)
    parser.add_argument("--observe-only", action="store_true", help="log breaches without sending any signal")
    args = parser.parse_args()
    if args.duration <= 0 or args.interval <= 0 or args.cpu_breach_samples < 1 or args.term_grace < 0:
        parser.error("duration, interval and breach count must be positive; grace must be nonnegative")
    if not 0 < args.max_host_cpu <= 100 or args.max_test_cpu <= 0:
        parser.error("host CPU limit must be in (0,100]; process CPU limit must be positive")
    if args.min_mem_available_mib < 0 or args.max_test_rss_mib <= 0 or args.max_fds < 1 or args.max_threads < 1:
        parser.error("invalid resource limits")
    if not args.run_id or len(args.pid) != len(set(args.pid)) or any(pid <= 1 for pid in args.pid):
        parser.error("run ID must be nonempty and PIDs must be distinct and greater than one")
    if (args.mode == "watch") != bool(args.pid):
        parser.error("watch requires explicit --pid entries; baseline accepts no PIDs")
    args.work_dir = args.work_dir.resolve()
    return args


def interrupted(signum, _frame):
    global STOP_SIGNAL
    STOP_SIGNAL = signum


def run(args, processes):
    start = time.monotonic()
    previous_host = None
    host_cpu_breaches = test_cpu_breaches = 0
    while True:
        now = time.monotonic()
        if OUTPUT_FAILED:
            return 1
        if STOP_SIGNAL is not None:
            emit("interrupted", signal=signal.Signals(STOP_SIGNAL).name)
            return 128 + STOP_SIGNAL
        if now - start >= args.duration:
            emit("complete" if args.mode == "baseline" else "time_limit", elapsed_seconds=round(now - start, 3))
            return 0 if args.mode == "baseline" else 124
        snapshot = host_snapshot()
        host = host_metrics(snapshot, previous_host)
        previous_host = snapshot
        samples = [sample for process in processes if (sample := process.sample(now)) is not None]
        total_rss = sum(sample["rss_bytes"] for sample in samples)
        total_cpu = sum(sample["cpu_percent"] or 0 for sample in samples)
        emit("sample", run_id=args.run_id, elapsed_seconds=round(now - start, 3), host=host,
             processes=samples, test_cpu_percent=round(total_cpu, 2), test_rss_bytes=total_rss)
        if args.mode == "watch" and not samples:
            emit("all_test_processes_exited")
            return 0
        host_cpu_breaches = host_cpu_breaches + 1 if (host["cpu_percent"] or 0) > args.max_host_cpu else 0
        test_cpu_breaches = test_cpu_breaches + 1 if total_cpu > args.max_test_cpu else 0
        reasons = []
        if host_cpu_breaches >= args.cpu_breach_samples:
            reasons.append("host_cpu")
        if test_cpu_breaches >= args.cpu_breach_samples:
            reasons.append("test_cpu")
        if host["mem_available_bytes"] < args.min_mem_available_mib * MIB:
            reasons.append("host_available_memory")
        if total_rss > args.max_test_rss_mib * MIB:
            reasons.append("test_rss")
        if any(s["fds"] > args.max_fds for s in samples):
            reasons.append("test_fds")
        if any(s["threads"] > args.max_threads for s in samples):
            reasons.append("test_threads")
        if reasons:
            emit("limit_exceeded", reasons=reasons, action="observe_only" if args.observe_only else "stop_registered_pids")
            if not args.observe_only:
                return 2
        time.sleep(min(args.interval, max(0, args.duration - (time.monotonic() - start))))


def main():
    args = parse_args()
    processes = []
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    try:
        for pid in args.pid:
            processes.append(GuardedProcess(pid, args.run_id, args.work_dir, args.observe_only))
        emit("start", run_id=args.run_id, mode=args.mode, cpu_count=os.cpu_count(),
             processes=[{"pid": p.pid, "start_ticks": p.start_ticks, "executable": p.executable} for p in processes],
             limits={k: v for k, v in vars(args).items() if k.startswith("max_") or k.startswith("min_")},
             interval_seconds=args.interval, cpu_breach_samples=args.cpu_breach_samples,
             duration_seconds=args.duration, observe_only=args.observe_only)
        return run(args, processes)
    except Exception as exc:
        emit("monitor_error", error=str(exc))
        return 1
    finally:
        if not args.observe_only:
            stop_processes(processes, args.term_grace)
        for process in processes:
            process.close()


if __name__ == "__main__":
    sys.exit(main())
