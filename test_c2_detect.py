import unittest
from c2_detect import BeaconDetector, Connection
from c2_detect import parse_generic_csv


class TestBeaconDetector(unittest.TestCase):

    def test_regular_beacon_is_flagged(self):
        """A tight ~60s interval pattern should be flagged as a beacon."""
        base = 1700000000
        conns = [
            Connection(base + i * 60, "10.0.0.1", "1.2.3.4", "443", 0.4, 200)
            for i in range(10)
        ]
        detector = BeaconDetector(min_connections=5, cov_threshold=0.30)
        results = detector.analyze(conns)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["is_beacon"])
        self.assertEqual(results[0]["confidence"], "HIGH")

    def test_irregular_traffic_is_not_flagged(self):
        """Randomly-timed connections should not be flagged."""
        import random
        random.seed(1)
        base = 1700000000
        t = base
        conns = []
        for _ in range(10):
            t += random.uniform(5, 500)
            conns.append(Connection(t, "10.0.0.2", "5.6.7.8", "443", 1.0, random.randint(500, 90000)))

        detector = BeaconDetector(min_connections=5, cov_threshold=0.30)
        results = detector.analyze(conns)
        self.assertEqual(len(results), 0)

    def test_below_min_connections_is_ignored(self):
        """Groups with fewer than min_connections should never be scored."""
        base = 1700000000
        conns = [
            Connection(base + i * 60, "10.0.0.3", "9.9.9.9", "53", 0.1, 80)
            for i in range(3)
        ]
        detector = BeaconDetector(min_connections=5, cov_threshold=0.30)
        results = detector.analyze(conns)
        self.assertEqual(len(results), 0)

    def test_groups_are_keyed_by_src_dst_port(self):
        """Different destination ports should form separate groups."""
        base = 1700000000
        conns = [
            Connection(base + i * 60, "10.0.0.1", "1.2.3.4", "443", 0.4, 200)
            for i in range(5)
        ] + [
            Connection(base + i * 60, "10.0.0.1", "1.2.3.4", "80", 0.4, 200)
            for i in range(5)
        ]
        detector = BeaconDetector(min_connections=5, cov_threshold=0.30)
        groups = detector.group_connections(conns)
        self.assertEqual(len(groups), 2)



    def test_invalid_csv_timestamp_reports_clear_error(self):
        import os
        import tempfile

        csv_content = (
            "timestamp,src_ip,dst_ip,dst_port,duration,bytes_sent\n"
            "not-a-timestamp,10.0.0.1,1.2.3.4,443,1,100\n"
        )

        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", suffix=".csv",
            delete=False
        ) as f:
            f.write(csv_content)
            file_path = f.name

        try:
            with self.assertRaisesRegex(ValueError, "row 2"):
                parse_generic_csv(file_path)
        finally:
            os.unlink(file_path)

if __name__ == "__main__":
    unittest.main()
