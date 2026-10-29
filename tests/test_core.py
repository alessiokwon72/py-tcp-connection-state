import os
import tempfile
import unittest

from py_tcp_connection_state import (
    TcpConnection,
    STATE_NAMES,
    USER_HZ,
    decode_state,
    parse_line,
    parse_tcp,
    parse_tcp6,
    parse_file,
)


class TestDecodeState(unittest.TestCase):
    def test_known_states(self):
        self.assertEqual(decode_state(1), "ESTABLISHED")
        self.assertEqual(decode_state(10), "LISTEN")
        self.assertEqual(decode_state(6), "TIME_WAIT")

    def test_unknown_state(self):
        # An integer outside the kernel's defined set returns UNKNOWN
        # rather than raising. This is documented in the README.
        self.assertEqual(decode_state(99), "UNKNOWN")


class TestParseLineIPv4(unittest.TestCase):
    HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"

    def test_header_returns_none(self):
        self.assertIsNone(parse_line(self.HEADER))

    def test_established_loopback(self):
        # 0100007F:2328  -> 127.0.0.1:9000
        # 00000000:0000  -> 0.0.0.0:0
        # st=01 (ESTABLISHED), tx=0, rx=0, timer 00:00, uid=0, inode=0
        line = "   0: 0100007F:2328 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000"
        conn = parse_line(line, ipv6=False)
        self.assertIsNotNone(conn)
        self.assertEqual(conn.local_ip, "127.0.0.1")
        self.assertEqual(conn.local_port, 9000)
        self.assertEqual(conn.remote_ip, "0.0.0.0")
        self.assertEqual(conn.remote_port, 0)
        self.assertEqual(conn.state, 1)
        self.assertEqual(conn.state_name, "ESTABLISHED")
        self.assertEqual(conn.tx_queue, 0)
        self.assertEqual(conn.rx_queue, 0)
        self.assertEqual(conn.timer_active, 0)
        self.assertEqual(conn.timer_duration, 0.0)
        self.assertEqual(conn.uid, 0)
        self.assertEqual(conn.inode, 0)

    def test_listen_state(self):
        # 00000000:1450 -> 0.0.0.0:5200 (0x1450 = 5200)
        # 00000000:0000 -> 0.0.0.0:0
        # st=0A (10 = LISTEN), inode=12345 (decimal)
        line = "   1: 00000000:1450 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000"
        conn = parse_line(line, ipv6=False)
        self.assertIsNotNone(conn)
        self.assertEqual(conn.local_port, 5200)
        self.assertEqual(conn.state, 10)
        self.assertEqual(conn.state_name, "LISTEN")
        self.assertEqual(conn.inode, 12345)

    def test_nonzero_queues_and_uid(self):
        # tx_queue:rx_queue column is 00000034:00000012
        # The kernel writes this as tx:rx, so tx=0x34=52, rx=0x12=18.
        # uid=1000 (decimal)
        line = "   2: 0100007F:0050 0100007F:0060 01 00000034:00000012 00:00000000 00000000   1000        0 99 1 0000000000000000"
        conn = parse_line(line, ipv6=False)
        self.assertIsNotNone(conn)
        self.assertEqual(conn.tx_queue, 52)
        self.assertEqual(conn.rx_queue, 18)
        self.assertEqual(conn.uid, 1000)
        self.assertEqual(conn.local_port, 80)
        self.assertEqual(conn.remote_port, 96)


class TestParseLineIPv6(unittest.TestCase):
    def test_loopback_ipv6(self):
        # 00000000000000000000000000000001 is ::1
        # port 0x2328 = 9000, scope 0x00
        local = "00000000000000000000000000000001:2328:00"
        remote = "00000000000000000000000000000000:0000:00"
        line = f"   0: {local} {remote} 01 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000"
        conn = parse_line(line, ipv6=True)
        self.assertIsNotNone(conn)
        self.assertEqual(conn.local_ip, "::1")
        self.assertEqual(conn.local_port, 9000)
        self.assertEqual(conn.remote_ip, "::")
        self.assertEqual(conn.remote_port, 0)
        self.assertEqual(conn.state_name, "ESTABLISHED")
        self.assertEqual(conn.ipv6_scope, 0)

    def test_ipv6_scope_id(self):
        # Scope ID 0x02 means interface index 2.
        local = "00000000000000000000000000000001:2328:02"
        remote = "00000000000000000000000000000000:0000:00"
        line = f"   0: {local} {remote} 01 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000"
        conn = parse_line(line, ipv6=True)
        self.assertIsNotNone(conn)
        self.assertEqual(conn.ipv6_scope, 2)


class TestParseTcp(unittest.TestCase):
    def test_full_parse_skips_header(self):
        text = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:2328 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000\n"
            "   1: 00000000:1450 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000\n"
        )
        conns = parse_tcp(text)
        self.assertEqual(len(conns), 2)
        self.assertEqual(conns[0].state_name, "ESTABLISHED")
        self.assertEqual(conns[1].state_name, "LISTEN")

    def test_truncated_final_line_skipped(self):
        # A short final line (kernel mid-write) must not raise.
        text = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:2328 00000000:0000 01 00000000\n"
        )
        conns = parse_tcp(text)
        self.assertEqual(conns, [])


class TestParseFile(unittest.TestCase):
    def test_ipv4_file(self):
        content = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:2328 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix="_tcp", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            conns = parse_file(path)
            self.assertEqual(len(conns), 1)
            self.assertEqual(conns[0].local_ip, "127.0.0.1")
        finally:
            os.unlink(path)

    def test_ipv6_file(self):
        content = (
            "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000000000000000000000000001:2328:00 00000000000000000000000000000000:0000:00 01 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix="tcp6", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            conns = parse_file(path)
            self.assertEqual(len(conns), 1)
            self.assertEqual(conns[0].local_ip, "::1")
            self.assertEqual(conns[0].ipv6_scope, 0)
        finally:
            os.unlink(path)


class TestTimerDuration(unittest.TestCase):
    def test_timer_duration_arithmetic(self):
        # timer column 01:0064 -> active=1, ticks=0x64=100
        # duration = 100 / USER_HZ = 1.0 second when USER_HZ=100
        line = "   0: 0100007F:2328 00000000:0000 01 00000000:00000000 01:00000064 00000000     0        0 0 1 0000000000000000"
        conn = parse_line(line, ipv6=False)
        self.assertIsNotNone(conn)
        self.assertEqual(conn.timer_active, 1)
        # Assert exact arithmetic, not float equality with a magic number.
        self.assertEqual(conn.timer_duration, 100 / USER_HZ)


class TestStateNamesComplete(unittest.TestCase):
    def test_all_documented_states_present(self):
        # The README implies coverage of the kernel's TCP state space.
        # We assert the map has the standard 12 entries so a future edit
        # does not silently drop one.
        for code, name in [
            (1, "ESTABLISHED"),
            (2, "SYN_SENT"),
            (3, "SYN_RECV"),
            (4, "FIN_WAIT1"),
            (5, "FIN_WAIT2"),
            (6, "TIME_WAIT"),
            (7, "CLOSE"),
            (8, "CLOSE_WAIT"),
            (9, "LAST_ACK"),
            (10, "LISTEN"),
            (11, "CLOSING"),
            (12, "NEW_SYN_RECV"),
        ]:
            self.assertEqual(STATE_NAMES[code], name)


if __name__ == "__main__":
    unittest.main()
