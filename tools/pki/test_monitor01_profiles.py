"""Isolated OpenSSL tests; no real CA, host, network, or deployment access."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
OPENSSL = shutil.which("openssl")


@unittest.skipUnless(OPENSSL, "OpenSSL is required; skipped tests are not a PASS")
class Monitor01Profiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="monitor01-profile-test-")
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.work = Path(cls.tmp.name)
        # Test-only RSA size and lifetime: these are not issuance policy.
        cls.run_ssl("req", "-new", "-x509", "-newkey", "rsa:2048",
                    "-nodes", "-keyout", "test-ca.key", "-out", "test-ca.pem",
                    "-days", "1", "-sha256", "-subj", "/CN=ISOLATED TEST CA",
                    "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                    "-addext", "subjectKeyIdentifier=hash")
        cls.run_ssl("req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", "test-leaf.key", "-out", "test-leaf.csr",
                    "-config", str(ROOT / "pki/monitor01-csr.cnf"))
        cls.run_ssl("x509", "-req", "-in", "test-leaf.csr", "-CA", "test-ca.pem",
                    "-CAkey", "test-ca.key", "-set_serial", "1", "-days", "1",
                    "-sha256", "-extfile", str(ROOT / "pki/monitor01-leaf.ext"),
                    "-extensions", "monitor01_leaf", "-out", "test-leaf.pem")

    @classmethod
    def run_ssl(cls, *args, check=True):
        return subprocess.run([OPENSSL, *args], cwd=cls.work, check=check,
                              text=True, capture_output=True, timeout=30,
                              env={**os.environ, "LC_ALL": "C"})

    def assert_only_monitor_ip(self, text):
        match = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*([^\n]+)", text)
        self.assertIsNotNone(match, "SAN missing from OpenSSL output")
        self.assertEqual(match.group(1).strip(), "IP Address:10.250.10.30")

    def test_csr_signature_and_exact_ip_san(self):
        self.run_ssl("req", "-in", "test-leaf.csr", "-verify", "-noout")
        output = self.run_ssl("req", "-in", "test-leaf.csr", "-text", "-noout").stdout
        self.assert_only_monitor_ip(output)

    def test_leaf_server_constraints_and_exact_ip_san(self):
        output = self.run_ssl("x509", "-in", "test-leaf.pem", "-text", "-noout").stdout
        self.assert_only_monitor_ip(output)
        self.assertRegex(output, r"X509v3 Basic Constraints: critical\s+CA:FALSE")
        self.assertRegex(output, r"X509v3 Key Usage: critical\s+Digital Signature, Key Encipherment")
        self.assertRegex(output, r"X509v3 Extended Key Usage:\s+TLS Web Server Authentication\s*\n")
        self.assertIn("X509v3 Subject Key Identifier:", output)
        self.assertIn("X509v3 Authority Key Identifier:", output)

    def test_csr_leaf_and_local_key_public_keys_match(self):
        csr = self.run_ssl("req", "-in", "test-leaf.csr", "-pubkey", "-noout").stdout
        leaf = self.run_ssl("x509", "-in", "test-leaf.pem", "-pubkey", "-noout").stdout
        local_key = self.run_ssl("pkey", "-in", "test-leaf.key", "-pubout").stdout
        self.assertEqual(csr, leaf)
        self.assertEqual(csr, local_key)

    def test_correct_ip_and_server_purpose_verify(self):
        self.run_ssl("verify", "-CAfile", "test-ca.pem", "-purpose", "sslserver",
                     "-verify_ip", "10.250.10.30", "test-leaf.pem")

    def test_wrong_ip_is_rejected(self):
        result = self.run_ssl("verify", "-CAfile", "test-ca.pem", "-purpose", "sslserver",
                              "-verify_ip", "10.1.93.54", "test-leaf.pem", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("IP address mismatch", result.stderr)

    def test_client_auth_purpose_is_rejected(self):
        result = self.run_ssl("verify", "-CAfile", "test-ca.pem", "-purpose", "sslclient",
                              "test-leaf.pem", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsuitable certificate purpose", result.stderr)


if __name__ == "__main__":
    unittest.main()
