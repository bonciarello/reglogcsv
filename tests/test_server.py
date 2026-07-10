"""
Test suite for RegLog CSV server.
Tests all supported log formats, error cases, and edge conditions.
"""

import io
import csv
import unittest
import json
from server import app, PARSERS, generate_csv


class TestParsers(unittest.TestCase):
    """Unit tests for individual log parsers."""

    # --- Apache Combined ---
    def test_apache_combined_valid(self):
        _, parser = PARSERS["apache_combined"]
        lines = [
            '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"',
            '192.168.1.1 - - [11/Oct/2023:14:22:00 +0000] "POST /api/login HTTP/1.1" 302 0 "https://mysite.com" "curl/7.79.1"',
        ]
        columns, rows = parser(lines)
        self.assertEqual(columns, ["IP", "Ident", "User", "Timestamp", "Method", "Path", "Protocol", "Status", "Size", "Referer", "UserAgent"])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], "127.0.0.1")
        self.assertEqual(rows[0][3], "10/Oct/2000:13:55:36 -0700")
        self.assertEqual(rows[0][4], "GET")
        self.assertEqual(rows[0][5], "/apache_pb.gif")
        self.assertEqual(rows[0][6], "HTTP/1.0")
        self.assertEqual(rows[0][7], "200")
        self.assertEqual(rows[0][8], "2326")
        self.assertEqual(rows[1][4], "POST")
        self.assertEqual(rows[1][5], "/api/login")
        self.assertEqual(rows[1][7], "302")
        self.assertEqual(rows[1][10], "curl/7.79.1")

    def test_apache_combined_empty_file(self):
        _, parser = PARSERS["apache_combined"]
        columns, rows = parser([])
        self.assertEqual(len(rows), 0)

    def test_apache_combined_no_match(self):
        _, parser = PARSERS["apache_combined"]
        lines = ["Questa non è una riga di log Apache", "Neanche questa"]
        columns, rows = parser(lines)
        self.assertEqual(len(rows), 0)

    def test_apache_combined_mixed(self):
        """Only valid lines are parsed, invalid ones are skipped."""
        _, parser = PARSERS["apache_combined"]
        lines = [
            '10.0.0.1 - - [01/Jan/2024:00:00:01 +0000] "GET / HTTP/1.1" 200 512 "-" "test/1.0"',
            "Questa è spazzatura",
            '10.0.0.2 - bob [01/Jan/2024:00:00:02 +0000] "DELETE /resource/42 HTTP/2" 204 0 "https://x.com" "test/2.0"',
        ]
        columns, rows = parser(lines)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], "10.0.0.1")
        self.assertEqual(rows[1][0], "10.0.0.2")
        self.assertEqual(rows[1][4], "DELETE")

    # --- Apache CLF ---
    def test_apache_clf_valid(self):
        _, parser = PARSERS["apache_clf"]
        lines = [
            '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326',
            '10.0.0.5 - alice [10/Oct/2023:14:01:00 +0000] "POST /login HTTP/1.1" 302 0',
        ]
        columns, rows = parser(lines)
        self.assertEqual(columns, ["IP", "Ident", "User", "Timestamp", "Method", "Path", "Protocol", "Status", "Size"])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], "127.0.0.1")
        self.assertEqual(rows[0][5], "/index.html")
        self.assertEqual(rows[1][4], "POST")

    def test_apache_clf_no_referer_useragent(self):
        """CLF lines should NOT have referer/useragent columns."""
        _, parser = PARSERS["apache_clf"]
        lines = [
            '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 2326',
        ]
        columns, rows = parser(lines)
        self.assertEqual(len(columns), 9)
        self.assertNotIn("Referer", columns)
        self.assertNotIn("UserAgent", columns)

    # --- Nginx ---
    def test_nginx_valid(self):
        _, parser = PARSERS["nginx"]
        lines = [
            '172.17.0.1 - - [15/Nov/2023:08:30:00 +0000] "GET /health HTTP/1.1" 200 2 "-" "Wget/1.21"',
        ]
        columns, rows = parser(lines)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "172.17.0.1")
        self.assertEqual(rows[0][5], "/health")
        self.assertEqual(rows[0][7], "200")

    # --- Syslog RFC 3164 ---
    def test_syslog_3164_valid(self):
        _, parser = PARSERS["syslog_3164"]
        lines = [
            "Oct 10 13:55:36 webserver sshd[12345]: Accepted publickey for alice from 192.168.1.100 port 54321",
            "Nov 15 08:30:00 myhost kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=10.0.0.1 DST=10.0.0.2",
        ]
        columns, rows = parser(lines)
        self.assertEqual(columns, ["Priority", "Timestamp", "Host", "Process", "PID", "Message"])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][1], "Oct 10 13:55:36")
        self.assertEqual(rows[0][2], "webserver")
        self.assertEqual(rows[0][3], "sshd")
        self.assertEqual(rows[0][4], "12345")
        self.assertIn("Accepted publickey", rows[0][5])

        self.assertEqual(rows[1][2], "myhost")
        self.assertEqual(rows[1][3], "kernel")
        self.assertEqual(rows[1][4], "")  # No PID
        self.assertIn("UFW BLOCK", rows[1][5])

    def test_syslog_3164_with_priority(self):
        _, parser = PARSERS["syslog_3164"]
        lines = [
            "<34>Oct 11 22:14:15 myhost app[100]: test message",
        ]
        columns, rows = parser(lines)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "34")  # Priority extracted
        self.assertEqual(rows[0][5], "test message")

    def test_syslog_3164_no_match(self):
        _, parser = PARSERS["syslog_3164"]
        lines = ["non syslog line"]
        columns, rows = parser(lines)
        self.assertEqual(len(rows), 0)

    # --- Syslog RFC 5424 ---
    def test_syslog_5424_valid(self):
        _, parser = PARSERS["syslog_5424"]
        lines = [
            '<34>1 2003-10-11T22:14:15.003Z myhost myapp 12345 ID47 - BOM\'su root\' failed',
            '<13>1 2024-01-15T10:30:00.000Z server nginx 42 msg1 [example@0 key="val"] request processed',
        ]
        columns, rows = parser(lines)
        self.assertEqual(columns, ["Priority", "Version", "Timestamp", "Host", "AppName", "ProcID", "MsgID", "StructuredData", "Message"])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], "34")
        self.assertEqual(rows[0][1], "1")
        self.assertEqual(rows[0][2], "2003-10-11T22:14:15.003Z")
        self.assertEqual(rows[0][3], "myhost")
        self.assertEqual(rows[0][4], "myapp")
        self.assertEqual(rows[0][7], "-")
        self.assertIn("BOM", rows[0][8])

    # --- CSV generation ---
    def test_csv_generation(self):
        columns = ["A", "B", "C"]
        rows = [["1", "2", "3"], ["x", "y", "z"]]
        csv_text = generate_csv(columns, rows)
        reader = csv.reader(io.StringIO(csv_text))
        parsed = list(reader)
        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[0], ["A", "B", "C"])
        self.assertEqual(parsed[1], ["1", "2", "3"])

    def test_csv_special_chars(self):
        """CSV should handle commas and quotes correctly."""
        columns = ["Campo", "Valore"]
        rows = [['"citazione"', "a,b,c"]]
        csv_text = generate_csv(columns, rows)
        reader = csv.reader(io.StringIO(csv_text))
        parsed = list(reader)
        self.assertEqual(parsed[1][0], '"citazione"')
        self.assertEqual(parsed[1][1], "a,b,c")


class TestAPI(unittest.TestCase):
    """Integration tests for Flask API endpoints."""

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    # --- Happy path ---
    def test_convert_apache_combined(self):
        log_content = '127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /api/status HTTP/1.1" 200 1234 "-" "curl/7.79"\n'
        data = {
            "file": (io.BytesIO(log_content.encode()), "access.log"),
            "format": "apache_combined",
        }
        resp = self.client.post("/api/convert", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.content_type)
        # Check CSV content
        csv_text = resp.data.decode("utf-8")
        lines = csv_text.strip().split("\r\n")
        self.assertGreaterEqual(len(lines), 2)  # header + at least 1 data row
        self.assertIn("IP", lines[0])
        self.assertIn("127.0.0.1", csv_text)

    def test_convert_apache_clf(self):
        log_content = '10.0.0.5 - alice [10/Oct/2023:14:01:00 +0000] "POST /login HTTP/1.1" 302 0\n'
        data = {
            "file": (io.BytesIO(log_content.encode()), "access.log"),
            "format": "apache_clf",
        }
        resp = self.client.post("/api/convert", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        csv_text = resp.data.decode("utf-8")
        self.assertIn("10.0.0.5", csv_text)
        self.assertIn("POST", csv_text)
        # CLF should NOT have Referer or UserAgent
        self.assertNotIn("Referer", csv_text.split("\r\n")[0])

    def test_convert_nginx(self):
        log_content = '172.17.0.1 - - [15/Nov/2023:08:30:00 +0000] "GET /health HTTP/1.1" 200 2 "-" "Wget/1.21"\n'
        data = {
            "file": (io.BytesIO(log_content.encode()), "nginx.log"),
            "format": "nginx",
        }
        resp = self.client.post("/api/convert", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        csv_text = resp.data.decode("utf-8")
        self.assertIn("172.17.0.1", csv_text)
        self.assertIn("/health", csv_text)

    def test_convert_syslog_3164(self):
        log_content = "Oct 10 13:55:36 webserver sshd[12345]: Accepted publickey for alice\n"
        data = {
            "file": (io.BytesIO(log_content.encode()), "syslog.log"),
            "format": "syslog_3164",
        }
        resp = self.client.post("/api/convert", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        csv_text = resp.data.decode("utf-8")
        self.assertIn("webserver", csv_text)
        self.assertIn("sshd", csv_text)
        self.assertIn("12345", csv_text)

    def test_convert_syslog_5424(self):
        log_content = '<34>1 2003-10-11T22:14:15.003Z myhost myapp 12345 ID47 - test message\n'
        data = {
            "file": (io.BytesIO(log_content.encode()), "syslog.log"),
            "format": "syslog_5424",
        }
        resp = self.client.post("/api/convert", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        csv_text = resp.data.decode("utf-8")
        self.assertIn("myhost", csv_text)
        self.assertIn("myapp", csv_text)
        self.assertIn("test message", csv_text)

    # --- Error cases ---
    def test_no_file(self):
        data = {"format": "apache_combined"}
        resp = self.client.post("/api/convert", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)
        err = json.loads(resp.data)
        self.assertIn("error", err)
        self.assertIn("Nessun file", err["error"])

    def test_empty_file(self):
        data = {
            "file": (io.BytesIO(b""), "empty.log"),
            "format": "apache_combined",
        }
        resp = self.client.post("/api/convert", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)
        err = json.loads(resp.data)
        self.assertIn("vuoto", err["error"].lower())

    def test_invalid_format(self):
        data = {
            "file": (io.BytesIO(b"some content"), "test.log"),
            "format": "invalid_format_xyz",
        }
        resp = self.client.post("/api/convert", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)
        err = json.loads(resp.data)
        self.assertIn("error", err)
        self.assertIn("Formato", err["error"])

    def test_no_matching_lines(self):
        """When format doesn't match any line, return error."""
        data = {
            "file": (io.BytesIO(b"This is not a log line\nAnother junk line\n"), "junk.txt"),
            "format": "apache_combined",
        }
        resp = self.client.post("/api/convert", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)
        err = json.loads(resp.data)
        self.assertIn("Nessuna riga riconosciuta", err["error"])

    def test_wrong_format_selection(self):
        """syslog content with apache format selected should fail."""
        data = {
            "file": (io.BytesIO(b"Oct 10 13:55:36 host proc[1]: msg\n"), "log.txt"),
            "format": "apache_combined",
        }
        resp = self.client.post("/api/convert", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)

    # --- Edge cases ---
    def test_multiple_lines(self):
        log_content = (
            '10.0.0.1 - - [01/Jan/2024:00:00:01 +0000] "GET /a HTTP/1.1" 200 100 "-" "t/1"\n'
            '10.0.0.2 - - [01/Jan/2024:00:00:02 +0000] "GET /b HTTP/1.1" 404 0 "-" "t/2"\n'
            '10.0.0.3 - - [01/Jan/2024:00:00:03 +0000] "GET /c HTTP/1.1" 500 50 "-" "t/3"\n'
        )
        data = {
            "file": (io.BytesIO(log_content.encode()), "big.log"),
            "format": "apache_combined",
        }
        resp = self.client.post("/api/convert", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        csv_text = resp.data.decode("utf-8")
        lines = csv_text.strip().split("\r\n")
        self.assertEqual(len(lines), 4)  # 1 header + 3 data

    def test_content_disposition(self):
        log_content = '127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 100 "-" "test"\n'
        data = {
            "file": (io.BytesIO(log_content.encode()), "my-server.log"),
            "format": "apache_combined",
        }
        resp = self.client.post("/api/convert", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        cd = resp.headers.get("Content-Disposition", "")
        self.assertIn("my-server_converted.csv", cd)

    def test_static_index(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"<!DOCTYPE html>", resp.data)

    def test_static_css(self):
        resp = self.client.get("/style.css")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"font-family", resp.data)

    def test_static_js(self):
        resp = self.client.get("/app.js")
        self.assertEqual(resp.status_code, 200)

    def test_robots_txt(self):
        resp = self.client.get("/robots.txt")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"User-agent", resp.data)

    def test_sitemap_xml(self):
        resp = self.client.get("/sitemap.xml")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"urlset", resp.data)


if __name__ == "__main__":
    unittest.main()
