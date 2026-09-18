"""Focused guards and real OpenSSL request reuse/export tests."""
import base64
import contextlib
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('monitor_csr', Path(__file__).with_name('create_monitor01_csr.py'))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class IdentityGuards(unittest.TestCase):
    def test_wrong_hostname_user_uid_and_ip(self):
        user = types.SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_dir='/home/server01_monitor')
        env = {'SUDO_USER': m.ACCOUNT, 'SUDO_UID': '1000'}
        valid = json.dumps([{'addr_info': [{'local': m.IP}]}]).encode()
        with mock.patch.object(m.os, 'geteuid', return_value=0), \
             mock.patch.object(m.pwd, 'getpwnam', return_value=user), \
             mock.patch.dict(m.os.environ, env, clear=True), \
             mock.patch.object(m.socket, 'gethostname', return_value='monitor01') as host, \
             mock.patch.object(m, 'run', return_value=valid) as run:
            self.assertEqual(m.identity(), user)
            host.return_value = 'harbor01'
            with self.assertRaises(m.Stop): m.identity()
            host.return_value = 'monitor01'
            with mock.patch.dict(m.os.environ, {'SUDO_USER': 'root'}):
                with self.assertRaises(m.Stop): m.identity()
            with mock.patch.dict(m.os.environ, {'SUDO_UID': '2000'}):
                with self.assertRaises(m.Stop): m.identity()
            run.return_value = b'[{"addr_info":[{"local":"10.1.93.54"}]}]'
            with self.assertRaises(m.Stop): m.identity()

    def test_plan_does_not_call_apply(self):
        with mock.patch.object(sys, 'argv', ['create_monitor01_csr.py']), \
             mock.patch.object(m, 'apply') as apply, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(), 0)
            self.assertEqual(json.loads(out.getvalue())['mode'], 'PLAN_ONLY')
            apply.assert_not_called()


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required; SKIP is not PASS')
class RequestGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='monitor-csr-test-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.fixture = Path(cls.temp.name) / 'fixture'
        cls.fixture.mkdir(mode=0o700)
        with mock.patch.object(m, 'REQUEST', cls.fixture), mock.patch.object(m, 'ROOT_UID', os.getuid()):
            cls.initial = m.prepare_request()

    def setUp(self):
        self.t = tempfile.TemporaryDirectory(prefix='monitor-csr-case-')
        self.addCleanup(self.t.cleanup)
        self.request = Path(self.t.name) / 'request'
        shutil.copytree(self.fixture, self.request)
        self.patch_request = mock.patch.object(m, 'REQUEST', self.request)
        self.patch_owner = mock.patch.object(m, 'ROOT_UID', os.getuid())
        self.patch_request.start(); self.patch_owner.start()
        self.addCleanup(self.patch_request.stop); self.addCleanup(self.patch_owner.stop)

    def test_reuse_verifies_request_without_second_key_generation(self):
        before = (self.request / 'monitor01.key').read_bytes()
        with mock.patch.object(m, 'run', wraps=m.run) as run:
            result = m.prepare_request()
            self.assertFalse(any('genpkey' in call.args[0] for call in run.call_args_list))
        self.assertEqual(result['receipt']['state'], 'REUSED')
        self.assertEqual(before, (self.request / 'monitor01.key').read_bytes())
        self.assertEqual(result['csr'], self.initial['csr'])

    def test_partial_request_stops_and_preserves_key(self):
        (self.request / 'request.json').unlink()
        before = (self.request / 'monitor01.key').read_bytes()
        with self.assertRaisesRegex(m.Stop, 'Partial request'): m.prepare_request()
        self.assertEqual(before, (self.request / 'monitor01.key').read_bytes())

    def test_profile_metadata_mismatch_stops(self):
        path = self.request / 'request.json'
        data = json.loads(path.read_text()); data['profile_sha256'] = '0' * 64
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(m.Stop, 'metadata mismatch'): m.prepare_request()

    def test_invalid_csr_stops(self):
        (self.request / 'monitor01.csr').write_text('invalid public request\n')
        with self.assertRaises(m.Stop): m.prepare_request()

    def test_symlink_and_unsafe_mode_stops(self):
        key = self.request / 'monitor01.key'
        key.chmod(0o644)
        with self.assertRaisesRegex(m.Stop, 'Unsafe private'): m.prepare_request()
        key.unlink(); key.symlink_to(self.fixture / 'monitor01.key')
        with self.assertRaisesRegex(m.Stop, 'Unsafe private'): m.prepare_request()

    def test_valid_pem_with_corrupt_signature_stops(self):
        csr = self.request / 'monitor01.csr'
        lines = csr.read_text().splitlines()
        der = bytearray(base64.b64decode(''.join(lines[1:-1])))
        der[-1] ^= 1
        b64 = base64.b64encode(der).decode()
        csr.write_text(lines[0] + '\n' + '\n'.join(b64[i:i+64] for i in range(0, len(b64), 64)) + '\n' + lines[-1] + '\n')
        with self.assertRaises(m.Stop): m.prepare_request()

    def test_openssl_environment_does_not_inherit_config_override(self):
        with mock.patch.dict(os.environ, {'OPENSSL_CONF': '/unexpected/config'}), \
             mock.patch.object(m.subprocess, 'run') as run:
            run.return_value = types.SimpleNamespace(returncode=0, stdout=b'ok', stderr=b'')
            m.run(['/usr/bin/openssl', 'version'])
            self.assertEqual(run.call_args.kwargs['env'], m.SAFE_ENV)
            self.assertNotIn('OPENSSL_CONF', run.call_args.kwargs['env'])

    def test_profile_hash_mismatch_stops(self):
        with mock.patch.object(m, 'EXPECTED_PROFILE_SHA', '0' * 64):
            with self.assertRaisesRegex(m.Stop, 'profile SHA256'): m.prepare_request()

    def test_symlink_directory_stops(self):
        link = Path(self.t.name) / 'linked'; link.symlink_to(self.request)
        with self.assertRaises(m.Stop): m.protected_dir(link)

    def test_key_mismatch_and_wrong_san_stop(self):
        key, csr = self.request / 'monitor01.key', self.request / 'monitor01.csr'
        m.run(['/usr/bin/openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
               'rsa_keygen_bits:3072', '-out', str(key)])
        with self.assertRaisesRegex(m.Stop, 'do not match'): m.prepare_request()
        m.run(['/usr/bin/openssl', 'req', '-new', '-key', str(key), '-out', str(csr),
               '-subj', '/C=KR/O=FDS/OU=Monitoring/CN=monitor01',
               '-addext', 'subjectAltName=IP:10.1.93.54'])
        with self.assertRaisesRegex(m.Stop, 'SAN differs'): m.prepare_request()

    def test_actual_archive_contains_only_public_members(self):
        # Under the test account home; world-writable ancestors are rejected.
        with tempfile.TemporaryDirectory(prefix='public-export-test-', dir=Path.home()) as out:
            payload = m.prepare_request()
            result = subprocess.run([sys.executable, '-I', '-B', '-c', m.EXPORT, out],
                                    input=json.dumps(payload), text=True, capture_output=True,
                                    check=True, timeout=30, preexec_fn=lambda: os.umask(0o077), env=m.SAFE_ENV)
            record = json.loads(result.stdout)
            with tarfile.open(record['archive'], 'r:gz') as archive:
                self.assertEqual(set(archive.getnames()), {'monitor01.csr', 'receipt.json', 'SHA256SUMS'})
                for member in archive.getmembers():
                    self.assertNotIn(b'PRIVATE KEY', archive.extractfile(member).read())
                for line in archive.extractfile('SHA256SUMS').read().decode().splitlines():
                    digest, member = line.split('  ', 1)
                    self.assertEqual(digest, hashlib.sha256(archive.extractfile(member).read()).hexdigest())
            self.assertEqual(record['sha256'], hashlib.sha256(Path(record['archive']).read_bytes()).hexdigest())
            self.assertTrue(Path(record['sidecar']).is_file())

    def test_export_payload_is_public_only(self):
        result = m.prepare_request()
        encoded = json.dumps(result)
        self.assertNotIn('PRIVATE KEY', encoded)
        self.assertEqual(set(result), {'csr', 'receipt'})
        self.assertIn('BEGIN CERTIFICATE REQUEST', result['csr'])
        user = types.SimpleNamespace(pw_uid=1000, pw_gid=1000)
        with mock.patch.object(m.subprocess, 'run') as run:
            run.return_value = types.SimpleNamespace(returncode=0, stdout=b'{"state":"REUSED"}')
            m.export_public(result, user, '/home/server01_monitor')
            self.assertEqual(json.loads(run.call_args.kwargs['input']), result)
            with mock.patch.object(m.os, 'setgroups') as groups, \
                 mock.patch.object(m.os, 'setgid') as gid, \
                 mock.patch.object(m.os, 'setuid') as uid, \
                 mock.patch.object(m.os, 'umask'):
                run.call_args.kwargs['preexec_fn']()
                groups.assert_called_once_with([])
                gid.assert_called_once_with(1000)
                uid.assert_called_once_with(1000)


if __name__ == '__main__':
    unittest.main()
