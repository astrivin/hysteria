import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest


# The monitor remains a sibling in both the repository and a copied test bundle.
ROOT = Path(__file__).resolve().parent


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.work = Path(self.temp.name)
        # Multicall coreutils dispatches on argv[0], so preserve the applet name.
        self.sleep = self.work / "sleep"
        shutil.copy2(shutil.which("sleep"), self.sleep)
        self.children = []

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=3)
        self.temp.cleanup()

    def sleeper(self, marker):
        child = subprocess.Popen([str(self.sleep), "30"], cwd=self.work,
                                 env={**os.environ, "HY2_VALIDATION_RUN_ID": marker})
        self.children.append(child)
        return child

    def run_monitor(self, mode, *args):
        result = subprocess.run([
            sys.executable, str(ROOT / "monitor.py"), mode, "--run-id", "owned-test",
            "--work-dir", str(self.work), "--duration", "0.2", "--interval", "0.05",
            "--max-host-cpu", "100", "--max-test-cpu", "10000",
            "--min-mem-available-mib", "0", "--term-grace", "0.2", *args,
        ], text=True, capture_output=True, timeout=5)
        return result, [json.loads(line) for line in result.stdout.splitlines()]

    def test_baseline_is_read_only(self):
        result, events = self.run_monitor("baseline")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        samples = [event for event in events if event["event"] == "sample"]
        self.assertGreaterEqual(len(samples), 2)
        self.assertIn("irq_percent", samples[-1]["host"])
        self.assertIn("softirq_percent", samples[-1]["host"])
        self.assertGreater(samples[-1]["host"]["mem_available_bytes"], 0)
        self.assertFalse(any(event["event"] == "signal" for event in events))

    @unittest.skipUnless(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "pidfd APIs unavailable")
    def test_limit_stops_only_registered_owned_pid(self):
        owned = self.sleeper("owned-test")
        other = self.sleeper("not-this-test")
        result, events = self.run_monitor("watch", "--pid", str(owned.pid), "--max-test-rss-mib", "0.001")
        self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
        owned.wait(timeout=2)
        self.assertIsNone(other.poll())
        signals = [event for event in events if event["event"] == "signal"]
        self.assertTrue(signals)
        self.assertEqual({event["pid"] for event in signals}, {owned.pid})

    def test_foreign_marker_is_never_signalled(self):
        other = self.sleeper("not-this-test")
        result, events = self.run_monitor("watch", "--pid", str(other.pid), "--max-test-rss-mib", "0.001")
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIsNone(other.poll())
        self.assertFalse(any(event["event"] == "signal" for event in events))


if __name__ == "__main__":
    unittest.main()
