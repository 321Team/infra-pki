"""Offline tests: no real CA mount, signing, private key or host mutation."""
import hashlib
import fcntl
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'tools/pki/monitor01-ca-console.sh'
DOC = ROOT / 'docs/MONITOR01_CA_SIGNING.md'


def shell(code, *args):
    return subprocess.run(
        ['/bin/bash', '--noprofile', '--norc', '-c',
         'source ' + shlex.quote(str(SCRIPT)) + '\n' + code, 'test', *map(str, args)],
        capture_output=True, text=True,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, timeout=10)


class MonitorCAConsole(unittest.TestCase):
    def test_actual_root_entry_defaults_to_plan(self):
        result = subprocess.run(['/bin/bash', str(ROOT / 'ca-start')],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PLAN_ONLY', result.stdout)
        self.assertIn('No CA operation executed.', result.stdout)

    def test_default_is_plan_without_privilege_or_tools(self):
        result = shell('identity() { exit 91; }; open_ca() { exit 92; }; main')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PLAN_ONLY', result.stdout)

    def test_explicit_execute_rejects_wrong_host(self):
        result = shell('id() { echo 0; }; hostname() { echo monitor01; }; identity')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('only for ca01', result.stderr)

    def test_explicit_execute_rejects_nonroot(self):
        result = shell('id() { echo 1000; }; identity')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('root console', result.stderr)

    def test_execution_requires_terminal(self):
        result = shell('id() { echo 0; }; hostname() { echo ca01; }; identity')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('interactive local terminal', result.stderr)

    def test_days_are_explicit_and_bounded(self):
        for value in ['1', '30', '365', '9999']:
            self.assertEqual(shell('valid_days "$1"', value).returncode, 0)
        for value in ['', '0', '-1', '01', '10000', '30.0', ' 30', '30;id']:
            self.assertNotEqual(shell('valid_days "$1"', value).returncode, 0)

    def test_approved_sign_block_is_byte_identical(self):
        expected = DOC.read_text().split('```bash\n', 1)[1].split('```', 1)[0]
        result = shell('extract_sign_block "$1"', DOC)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, expected)
        self.assertEqual(hashlib.sha256(DOC.read_bytes()).hexdigest(),
                         'f707908e926e1e58c75d453233133c03d63dc63c554ca295aad87eeb914d1728')
        self.assertEqual(hashlib.sha256(expected.encode()).hexdigest(),
                         '8cb9e2009b8bd190665906124fc88a2ab1b161cf6d433791d911385c107d2236')

    def test_sign_dispatch_retains_exact_block_and_explicit_inputs(self):
        expected = DOC.read_text().split('```bash\n', 1)[1].split('```', 1)[0]
        result = shell('env() { printf "%s" "${!#}"; }; sign_request /request "$1" 30', ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, expected)

    def test_unsafe_directory_and_symlink_rejected(self):
        result = shell('safe_dir /tmp')
        self.assertNotEqual(result.returncode, 0)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target'
            target.mkdir()
            link = Path(directory) / 'link'
            link.symlink_to(target, target_is_directory=True)
            result = shell('safe_dir "$1"', link)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('linked directory', result.stderr)

    def test_public_hash_mismatch_stops_before_crypto(self):
        with tempfile.NamedTemporaryFile() as public:
            public.write(b'public-input')
            public.flush()
            result = shell('safe_file() { :; }; check_hash "$1" bad', public.name)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('SHA256 mismatch', result.stderr)

    def test_concurrent_helper_lock_is_rejected(self):
        with tempfile.NamedTemporaryFile() as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = shell('safe_dir() { :; }; safe_file() { :; }; MON_LOCK=$1; lock_console', lock.name)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Another console helper', result.stderr)

    def test_modified_sign_block_never_invokes_bash(self):
        result = shell('extract_sign_block() { echo "exit 0"; }; env() { exit 91; }; sign_request /request /source 30')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(result.returncode, 91)
        self.assertIn('signing block SHA256 mismatch', result.stderr)

    def test_wrong_active_volume_is_rejected(self):
        result = shell('''
cryptsetup() {
  case "$1" in
    status) printf '  device: /dev/fake-ca\n';;
    luksUUID) printf 'different-volume\n';;
  esac
}
check_mapping
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('wrong CA UUID', result.stderr)

    def test_correct_active_volume_is_reused(self):
        result = shell('''
cryptsetup() {
  case "$1" in
    status) printf '  device: /dev/fake-ca\n';;
    luksUUID) printf '%s\n' "$MON_CA_UUID";;
    *) exit 91;;
  esac
}
check_mapping
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_mounted_volume_wrong_source_stops_without_remount(self):
        result = shell('''
cryptsetup() { return 0; }
check_mapping() { :; }
safe_dir() { :; }
MON_MOUNT=/
mountpoint() { return 0; }
mount() { exit 91; }
findmnt() { echo /dev/wrong; }
readlink() { printf '%s\n' "${!#}"; }
open_ca
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(result.returncode, 91)
        self.assertIn('Wrong filesystem', result.stderr)

    def test_existing_mount_reused_without_setting_changes(self):
        result = shell('''
cryptsetup() { return 0; }
check_mapping() { :; }
safe_dir() { :; }
MON_MOUNT=/
mountpoint() { return 0; }
mount() { exit 91; }
findmnt() { if [[ "$*" == *SOURCE* ]]; then echo /dev/mapper/fds-ca; else echo rw,nodev,nosuid,noexec,relatime; fi; }
readlink() { printf '%s\n' "${!#}"; }
open_ca
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('EXISTING_CA_VOLUME=PASS', result.stdout)

    def test_existing_mount_without_required_flags_is_not_remounted(self):
        result = shell('''
cryptsetup() { return 0; }
check_mapping() { :; }
safe_dir() { :; }
MON_MOUNT=/
mountpoint() { return 0; }
mount() { exit 91; }
findmnt() { if [[ "$*" == *SOURCE* ]]; then echo /dev/mapper/fds-ca; else echo rw,nodev,nosuid; fi; }
readlink() { printf '%s\n' "${!#}"; }
open_ca
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(result.returncode, 91)
        self.assertIn('noexec (not remounted)', result.stderr)

    def test_closed_volume_is_opened_once_and_mounted_with_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            result = shell('''
mon_opened=no; mon_open_count=0; mon_mount_count=0
MON_MOUNT=$1
safe_dir() { :; }
cryptsetup() {
 case "$1" in
   status) [[ "$mon_opened" == yes ]] || return 4; printf 'device: /dev/fake-ca\n';;
   luksUUID) printf '%s\n' "$MON_CA_UUID";;
   open) mon_opened=yes; mon_open_count=$((mon_open_count + 1));;
   *) exit 91;;
 esac
}
mountpoint() { return 1; }
mount() { [[ "$*" == '-o nodev,nosuid,noexec /dev/mapper/fds-ca '* ]] || exit 92; mon_mount_count=$((mon_mount_count + 1)); }
findmnt() {
 case "$*" in
   *SOURCE*) echo /dev/mapper/fds-ca;;
   *OPTIONS*) echo rw,nodev,nosuid,noexec;;
   *) return 1;;
 esac
}
readlink() { printf '%s\n' "${!#}"; }
open_ca
printf 'OPEN=%s MOUNT=%s\n' "$mon_open_count" "$mon_mount_count"
''', directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('OPEN=1 MOUNT=1', result.stdout)

    def test_wrong_root_is_rejected_before_output(self):
        result = shell('safe_file() { :; }; safe_dir() { :; }; openssl() { echo "sha256 Fingerprint=00:01"; }; check_ca_state')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Root fingerprint mismatch', result.stderr)

    def test_partial_output_and_ledger_entry_prevent_reissue(self):
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory)
            index = ca / 'index.txt'
            index.write_text('')
            output = ca / 'monitor01.crt'
            output.write_bytes(b'partial')
            prefix = '''
safe_file() { :; }; safe_dir() { :; }
openssl() { printf 'sha256 Fingerprint=%s\n' "$MON_ROOT_FP"; }
MON_CA_DIR=$1; MON_OUTPUT=$2
check_ca_state
'''
            result = shell(prefix, ca, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('output already exists', result.stderr)
            self.assertEqual(output.read_bytes(), b'partial')
            output.unlink()
            index.write_text('V\t270101000000Z\t\t1002\tunknown\t/C=KR/O=FDS/OU=Monitoring/CN=monitor01\n')
            result = shell(prefix, ca, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('ledger entry already exists', result.stderr)
            self.assertFalse(output.exists())

    def test_missing_request_output_is_allowed_with_other_ledger_subject(self):
        with tempfile.TemporaryDirectory() as directory:
            ca = Path(directory)
            (ca / 'index.txt').write_text('V\t270101000000Z\t\t1000\tunknown\t/C=KR/CN=harbor01\n')
            result = shell('''
safe_file() { :; }; safe_dir() { :; }
openssl() { printf 'sha256 Fingerprint=%s\n' "$MON_ROOT_FP"; }
MON_CA_DIR=$1; MON_OUTPUT=$1/monitor01.crt
check_ca_state
''', ca)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_signed_request_verification_requires_positive_result(self):
        result = shell('''
check_hash() { :; }
openssl() { echo 'Certificate request self-signature verify failure'; }
check_request /request /source
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('did not confirm success', result.stderr)

    def test_expected_csr_identity_and_san_pass(self):
        result = shell('''
check_hash() { :; }
openssl() {
 case "$*" in
  *-verify*) echo 'Certificate request self-signature verify OK';;
  *-subject*) echo 'subject=CN=monitor01,OU=Monitoring,O=FDS,C=KR';;
  *-text*) printf 'Public Key Algorithm: rsaEncryption\nPublic-Key: (3072 bit)\nX509v3 Subject Alternative Name:\n    IP Address:10.250.10.30\n';;
 esac
}
check_request /request /source
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('REQUEST_AND_APPROVED_SOURCE=PASS', result.stdout)

    def test_extra_csr_san_rejected(self):
        result = shell('''
check_hash() { :; }
openssl() {
 case "$*" in
  *-verify*) echo 'Certificate request self-signature verify OK';;
  *-subject*) echo 'subject=CN=monitor01,OU=Monitoring,O=FDS,C=KR';;
  *-text*) printf 'Public Key Algorithm: rsaEncryption\nPublic-Key: (3072 bit)\nX509v3 Subject Alternative Name:\n    IP Address:10.250.10.30, DNS:monitor01\n';;
 esac
}
check_request /request /source
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SAN mismatch', result.stderr)


if __name__ == '__main__':
    unittest.main()
