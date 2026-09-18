#!/usr/bin/env python3
"""Create/reuse one protected monitor01 request; export public material only."""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
REQUEST = Path('/etc/fds/pki/monitor01/request')
PROFILE = ROOT / 'pki/monitor01-csr.cnf'
LEAF_PROFILE = ROOT / 'pki/monitor01-leaf.ext'
EXPECTED_PROFILE_SHA = '69ff9d34ad0f257d76ef5ab31c1b35982a33c9234c99d52ea6b16eeed4adaab6'
ROOT_UID = 0
ACCOUNT = 'server01_monitor'
IP = '10.250.10.30'
SAFE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}


class Stop(RuntimeError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(args, data=None, require_verify_ok=False):
    result = subprocess.run(args, input=data, capture_output=True, timeout=45,
                            env=SAFE_ENV)
    if result.returncode:
        raise Stop('Command failed: ' + args[0] + ' ' + args[1])
    if require_verify_ok and not re.search(
            rb'(?m)^(?:Certificate request self-signature )?verify OK\r?$',
            result.stdout + result.stderr):
        raise Stop('CSR signature verification did not report success')
    return result.stdout


def identity():
    if os.geteuid() != 0:
        raise Stop('--apply requires sudo from server01_monitor')
    if socket.gethostname().split('.')[0] != 'monitor01':
        raise Stop('Wrong hostname')
    if os.environ.get('SUDO_USER') != ACCOUNT:
        raise Stop('Wrong sudo account')
    user = pwd.getpwnam(ACCOUNT)
    if user.pw_uid == 0 or os.environ.get('SUDO_UID') != str(user.pw_uid):
        raise Stop('Sudo UID does not match login account')
    interfaces = json.loads(run(['/usr/sbin/ip', '-j', '-4', 'address', 'show', 'dev', 'ens160']))
    if not any(a.get('local') == IP for i in interfaces for a in i.get('addr_info', [])):
        raise Stop('Expected IP is absent from ens160')
    return user


def protected_dir(path, create=False):
    """Every ancestor must be a root-owned, non-writable, real directory."""
    path = Path(path)
    if not path.is_absolute():
        raise Stop('Private path must be absolute')
    for part in reversed([path, *path.parents]):
        if create and not part.exists() and not part.is_symlink():
            part.mkdir(mode=0o700)
        try:
            info = part.lstat()
        except FileNotFoundError as exc:
            raise Stop('Private directory is missing') from exc
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o022:
            raise Stop('Unsafe private directory')
    if stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise Stop('Private request directory must have mode 0700')


def private_file(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise Stop('Unsafe private request file')


def exclusive_file(path, content=b''):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def verify_request(key, csr):
    run(['/usr/bin/openssl', 'req', '-in', str(csr), '-verify', '-noout'], require_verify_ok=True)
    text = run(['/usr/bin/openssl', 'req', '-in', str(csr), '-text', '-noout']).decode()
    sans = re.search(r'X509v3 Subject Alternative Name:\s*\n\s*([^\n]+)', text)
    if not sans or sans.group(1).strip() != 'IP Address:' + IP:
        raise Stop('CSR SAN differs from approved monitor01 IP')
    subject = run(['/usr/bin/openssl', 'req', '-in', str(csr), '-subject', '-nameopt', 'RFC2253', '-noout']).decode().strip()
    if subject != 'subject=CN=monitor01,OU=Monitoring,O=FDS,C=KR':
        raise Stop('CSR subject differs from monitor01 profile')
    csr_pub = run(['/usr/bin/openssl', 'req', '-in', str(csr), '-pubkey', '-noout'])
    key_pub = run(['/usr/bin/openssl', 'pkey', '-in', str(key), '-pubout'])
    if csr_pub != key_pub:
        raise Stop('CSR and local key do not match')
    public_text = run(['/usr/bin/openssl', 'pkey', '-pubin', '-text', '-noout'], csr_pub).decode()
    if 'Public-Key: (3072 bit)' not in public_text or 'Modulus:' not in public_text:
        raise Stop('Request must use the proposed RSA3072 profile')
    return digest(csr.read_bytes()), digest(csr_pub)


def prepare_request():
    profile_sha = digest(PROFILE.read_bytes())
    if PROFILE.is_symlink() or profile_sha != EXPECTED_PROFILE_SHA:
        raise Stop('CSR profile SHA256 mismatch')
    key, csr, meta = [REQUEST / n for n in ('monitor01.key', 'monitor01.csr', 'request.json')]
    known = {key.name, csr.name, meta.name, '.request.lock'}
    if any(p.name not in known for p in REQUEST.iterdir()):
        raise Stop('Unknown files in request directory; preserve and review')
    present = [p.exists() or p.is_symlink() for p in (key, csr, meta)]
    if any(present) and not all(present):
        raise Stop('Partial request exists; preserved without overwrite')
    if all(present):
        for path in (key, csr, meta):
            private_file(path)
        info = json.loads(meta.read_text())
        csr_sha, pub_sha = verify_request(key, csr)
        if (info.get('schema') != 'fds.monitor01-csr-request.v1'
                or info.get('profile_sha256') != profile_sha
                or info.get('csr_sha256') != csr_sha
                or info.get('public_key_sha256') != pub_sha):
            raise Stop('Existing request metadata mismatch')
        state = 'REUSED'
    else:
        exclusive_file(key)
        run(['/usr/bin/openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
             'rsa_keygen_bits:3072', '-out', str(key)])
        exclusive_file(csr)
        run(['/usr/bin/openssl', 'req', '-new', '-key', str(key), '-config', str(PROFILE), '-out', str(csr)])
        csr_sha, pub_sha = verify_request(key, csr)
        info = {'schema': 'fds.monitor01-csr-request.v1',
                'created_at': dt.datetime.now(dt.timezone.utc).isoformat(),
                'profile_sha256': profile_sha, 'csr_sha256': csr_sha,
                'public_key_sha256': pub_sha, 'source_sha256': digest(Path(__file__).read_bytes())}
        exclusive_file(meta, (json.dumps(info, sort_keys=True, indent=2) + '\n').encode())
        for path in (key, csr, meta):
            private_file(path)
        state = 'CREATED'
    receipt = {**info, 'state': state, 'hostname': 'monitor01', 'account': ACCOUNT,
               'exported_at': dt.datetime.now(dt.timezone.utc).isoformat(),
               'current_source_sha256': digest(Path(__file__).read_bytes()),
               'leaf_profile_sha256': digest(LEAF_PROFILE.read_bytes()),
               'runtime_tls_deployed': False}
    return {'csr': csr.read_text(), 'receipt': receipt}


# Runs only AFTER setuid/setgid; stdin holds public CSR + public receipt only.
EXPORT = r'''
import hashlib, io, json, os, pathlib, stat, sys, tarfile, tempfile
out = pathlib.Path(sys.argv[1])
if not out.is_absolute():
    raise RuntimeError('Output directory must be absolute')
for part in [out, *out.parents]:
    st = part.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o022:
        raise RuntimeError('Unsafe output directory')
if out.stat().st_uid != os.getuid():
    raise RuntimeError('Output directory must belong to login account')
data = json.load(sys.stdin)
files = {'monitor01.csr': data['csr'].encode(),
         'receipt.json': (json.dumps(data['receipt'], sort_keys=True, indent=2)+'\n').encode()}
files['SHA256SUMS'] = ''.join(hashlib.sha256(v).hexdigest()+'  '+k+'\n' for k,v in files.items()).encode()
fd, name = tempfile.mkstemp(prefix='FDS_MONITOR01_CSR_', suffix='.tar.gz', dir=out)
with os.fdopen(fd, 'wb') as raw:
    with tarfile.open(fileobj=raw, mode='w:gz') as archive:
        for member, content in files.items():
            entry = tarfile.TarInfo(member)
            entry.size, entry.mode = len(content), 0o600
            archive.addfile(entry, io.BytesIO(content))
sha = hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()
with open(name+'.sha256', 'x') as f:
    f.write(sha+'  '+pathlib.Path(name).name+'\n')
print(json.dumps({'state': data['receipt']['state'], 'archive': name,
                  'sidecar': name+'.sha256', 'sha256': sha}, sort_keys=True))
'''


def export_public(payload, user, output_dir):
    def drop():
        os.setgroups([])
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)
        os.umask(0o077)
    result = subprocess.run([sys.executable, '-I', '-B', '-c', EXPORT, str(output_dir)],
                            input=json.dumps(payload).encode(), capture_output=True,
                            timeout=30, preexec_fn=drop, cwd='/', env=SAFE_ENV)
    if result.returncode:
        raise Stop('Public export failed; protected request preserved for retry')
    return json.loads(result.stdout)


def apply(output_dir=None):
    user = identity()
    os.umask(0o077)
    protected_dir(REQUEST, create=True)
    fd = os.open(REQUEST / '.request.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        private_file(REQUEST / '.request.lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        payload = prepare_request()
        return export_public(payload, user, output_dir or user.pw_dir)
    except BlockingIOError as exc:
        raise Stop('Another request operation is active') from exc
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    try:
        if args.apply:
            result = apply(args.output_dir)
        else:
            result = {'mode': 'PLAN_ONLY', 'hostname': 'monitor01', 'account': ACCOUNT,
                      'ip_san': IP, 'key_algorithm_proposal': 'RSA3072',
                      'private_request_path': str(REQUEST), 'mutation_attempted': False,
                      'export': 'public CSR, receipt, SHA256SUMS only'}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Stop, OSError, ValueError, subprocess.SubprocessError) as exc:
        # Do not print OpenSSL stderr, configuration, or any private file bytes.
        message = str(exc) if isinstance(exc, Stop) else type(exc).__name__
        print(json.dumps({'status': 'STOP', 'error': message}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
