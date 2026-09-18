#!/usr/bin/env bash
# Offline ca01 console helper. CA signing stays in the pinned, reviewed document.
set -Eeuo pipefail

MON_CA_UUID=ef015461-83d1-41f9-a1c7-cd6c471644f1
MON_CSR_SHA=37fda6d9fb99f101bf213a8e6a070c3e6dce3ba5238b54f178d9c62c8ddd3fa1
MON_RECEIPT_SHA=fe93ac26b6ca2b2c8ad4fa77eec2c7bf5b44b6777c9fb62d58846c6f02ba9dce
MON_PROFILE_SHA=793962aab657fc833219aa020ee50f841f4ef4aeda08499815f2f1d51d614448
MON_DOC_SHA=f707908e926e1e58c75d453233133c03d63dc63c554ca295aad87eeb914d1728
MON_SIGN_SHA=8cb9e2009b8bd190665906124fc88a2ab1b161cf6d433791d911385c107d2236
MON_ROOT_FP=6a75baf4dbe03ef24cce944e616384d318f7ca919cd7bd914624b4cebac06b10
MON_MOUNT=/mnt/fds-ca
MON_CA_DIR=$MON_MOUNT/fds-project-root-ca-2026-replacement
MON_OUTPUT=$MON_CA_DIR/requests/monitor01-37fda6d9fb99/monitor01.crt
MON_LOCK=/run/fds-monitor01-ca-console.lock

stop() { printf 'STOP: %s\n' "$*" >&2; exit 2; }

safe_dir() {
  local mon_path=$1 mon_uid mon_mode
  [[ "$mon_path" == /* && "$mon_path" != *'/../'* && "$mon_path" != */.. &&
     "$mon_path" != *'/./'* && "$mon_path" != */. ]] || stop 'Unsafe absolute directory path'
  while :; do
    [[ -d "$mon_path" && ! -L "$mon_path" ]] || stop "Missing or linked directory: $mon_path"
    read -r mon_uid mon_mode < <(stat -c '%u %a' -- "$mon_path")
    [[ "$mon_uid" == 0 ]] && (( (8#$mon_mode & 022) == 0 )) || stop "Unsafe directory owner/mode: $mon_path"
    [[ "$mon_path" == / ]] && break
    mon_path=$(dirname -- "$mon_path")
  done
}

safe_file() {
  local mon_file=$1 mon_uid mon_mode mon_links
  safe_dir "$(dirname -- "$mon_file")"
  [[ -f "$mon_file" && ! -L "$mon_file" ]] || stop "Missing or linked file: $mon_file"
  read -r mon_uid mon_mode mon_links < <(stat -c '%u %a %h' -- "$mon_file")
  [[ "$mon_uid" == 0 && "$mon_links" == 1 ]] && (( (8#$mon_mode & 022) == 0 )) || stop "Unsafe file owner/mode: $mon_file"
}

check_hash() {
  safe_file "$1"
  [[ "$(sha256sum -- "$1" | cut -d' ' -f1)" == "$2" ]] || stop "SHA256 mismatch: $1"
}

extract_sign_block() {
  # Only the first Bash fence; awk retains the approved final newline.
  awk '/^```bash$/ {if (!seen++) {inside=1; next}}
       inside && /^```$/ {exit} inside {print}' "$1"
}

valid_days() { [[ "$1" =~ ^[1-9][0-9]{0,3}$ ]]; }

identity() {
  [[ "$(id -u)" == 0 ]] || stop 'Run from the existing root console'
  [[ "$(hostname -s)" == ca01 ]] || stop 'This operation is only for ca01'
  [[ -t 0 && -t 1 && -t 2 ]] || stop 'An interactive local terminal is required'
}

lock_console() {
  safe_dir /run
  if [[ ! -e "$MON_LOCK" && ! -L "$MON_LOCK" ]]; then
    (umask 077; set -C; : > "$MON_LOCK") || stop 'Cannot create local operation lock'
  fi
  safe_file "$MON_LOCK"
  [[ "$(stat -c '%a' -- "$MON_LOCK")" == 600 ]] || stop 'Lock mode must be 0600'
  exec {MON_LOCK_FD}<> "$MON_LOCK"
  flock -n "$MON_LOCK_FD" || stop 'Another console helper is running'
  # This coordinates this helper only, not unrelated openssl commands.
}

check_request() {
  local mon_request=$1 mon_root=$2 mon_verify mon_subject mon_text
  check_hash "$mon_root/docs/MONITOR01_CA_SIGNING.md" "$MON_DOC_SHA"
  check_hash "$mon_root/pki/monitor01-leaf.ext" "$MON_PROFILE_SHA"
  check_hash "$mon_request/monitor01.csr" "$MON_CSR_SHA"
  check_hash "$mon_request/receipt.json" "$MON_RECEIPT_SHA"
  mon_verify=$(openssl req -in "$mon_request/monitor01.csr" -verify -noout 2>&1) || stop 'CSR signature command failed'
  case "$mon_verify" in
    'Certificate request self-signature verify OK'|'verify OK') ;;
    *) stop 'CSR signature verification did not confirm success' ;;
  esac
  mon_subject=$(openssl req -in "$mon_request/monitor01.csr" -subject -nameopt RFC2253 -noout)
  [[ "$mon_subject" == 'subject=CN=monitor01,OU=Monitoring,O=FDS,C=KR' ]] || stop 'CSR subject mismatch'
  mon_text=$(openssl req -in "$mon_request/monitor01.csr" -text -noout)
  [[ "$mon_text" == *'Public-Key: (3072 bit)'* && "$mon_text" == *'Public Key Algorithm: rsaEncryption'* ]] || stop 'CSR public key mismatch'
  [[ "$(printf '%s\n' "$mon_text" | awk '/X509v3 Subject Alternative Name:/ {getline; sub(/^[[:space:]]+/, ""); print}')" == 'IP Address:10.250.10.30' ]] || stop 'CSR SAN mismatch'
  printf 'REQUEST_AND_APPROVED_SOURCE=PASS\n'
}

check_mapping() {
  local mon_status mon_device mon_uuid
  mon_status=$(cryptsetup status fds-ca) || stop 'CA mapping is not active'
  mon_device=$(printf '%s\n' "$mon_status" | awk '$1 == "device:" {print $2}')
  [[ "$mon_device" == /* && "$mon_device" != *$'\n'* ]] || stop 'Cannot identify CA mapping device'
  mon_uuid=$(cryptsetup luksUUID "$mon_device") || stop 'Cannot read CA volume UUID'
  [[ "$mon_uuid" == "$MON_CA_UUID" ]] || stop 'Active mapping has the wrong CA UUID'
}

open_ca() {
  local mon_source mon_options mon_option mon_device=/dev/disk/by-uuid/$MON_CA_UUID
  if cryptsetup status fds-ca >/dev/null 2>&1; then
    check_mapping
  else
    [[ ! -e /dev/mapper/fds-ca && ! -L /dev/mapper/fds-ca ]] || stop 'Unexpected inactive CA mapping path'
    [[ "$(cryptsetup luksUUID "$mon_device")" == "$MON_CA_UUID" ]] || stop 'Expected CA volume not found'
    printf 'Enter the existing CA volume passphrase at the cryptsetup prompt.\n'
    cryptsetup open --type luks "$mon_device" fds-ca
    check_mapping
  fi
  safe_dir /mnt
  if [[ ! -e "$MON_MOUNT" && ! -L "$MON_MOUNT" ]]; then
    mkdir -m 700 -- "$MON_MOUNT"
  fi
  safe_dir "$MON_MOUNT"
  if ! mountpoint -q -- "$MON_MOUNT"; then
    # A different existing mount of this filesystem is not used implicitly.
    if findmnt -rn -S /dev/mapper/fds-ca -o TARGET | read -r mon_source; then
      stop 'CA volume is already mounted at another path'
    fi
    mount -o nodev,nosuid,noexec /dev/mapper/fds-ca "$MON_MOUNT"
  fi
  mon_source=$(findmnt -rn -o SOURCE --mountpoint "$MON_MOUNT")
  [[ "$(readlink -f -- "$mon_source")" == "$(readlink -f /dev/mapper/fds-ca)" ]] || stop 'Wrong filesystem at CA mountpoint'
  mon_options=$(findmnt -rn -o OPTIONS --mountpoint "$MON_MOUNT")
  for mon_option in rw nodev nosuid noexec; do
    [[ ",$mon_options," == *,"$mon_option",* ]] || stop "Existing CA mount lacks required option: $mon_option (not remounted)"
  done
  safe_dir "$MON_CA_DIR"
  printf 'EXISTING_CA_VOLUME=PASS\n'
}

check_ca_state() {
  local mon_fp mon_existing
  safe_file "$MON_CA_DIR/root-ca.cnf"
  safe_file "$MON_CA_DIR/certs/fds-root-ca.crt"
  safe_file "$MON_CA_DIR/index.txt"
  safe_file "$MON_CA_DIR/serial"
  safe_dir "$MON_CA_DIR/newcerts"
  mon_fp=$(openssl x509 -in "$MON_CA_DIR/certs/fds-root-ca.crt" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
  [[ "$mon_fp" == "$MON_ROOT_FP" ]] || stop 'Existing Root fingerprint mismatch'
  [[ ! -e "$MON_OUTPUT" && ! -L "$MON_OUTPUT" ]] || stop 'Leaf output already exists; preserved without reissue'
  mon_existing=$(awk -F '\t' '$6 ~ /(^|\/)CN=monitor01(\/|$)/ {print $4}' "$MON_CA_DIR/index.txt")
  [[ -z "$mon_existing" ]] || stop 'A monitor01 ledger entry already exists; preserve and verify that issuance'
}

prepare_output() {
  local mon_dir
  for mon_dir in "$MON_CA_DIR/requests" "$(dirname -- "$MON_OUTPUT")"; do
    if [[ ! -e "$mon_dir" && ! -L "$mon_dir" ]]; then
      mkdir -m 700 -- "$mon_dir"
    fi
    safe_dir "$mon_dir"
    [[ "$(stat -c '%a' -- "$mon_dir")" == 700 ]] || stop 'Request directory must have mode 0700'
  done
}

sign_request() {
  local mon_request=$1 mon_root=$2 mon_days=$3 mon_block
  # Sentinel prevents command substitution from trimming the approved newline.
  mon_block=$(extract_sign_block "$mon_root/docs/MONITOR01_CA_SIGNING.md"; printf '.')
  mon_block=${mon_block%.}
  [[ -n "$mon_block" ]] || stop 'Approved signing block is missing'
  [[ "$(printf '%s' "$mon_block" | sha256sum | cut -d' ' -f1)" == "$MON_SIGN_SHA" ]] || stop 'Approved signing block SHA256 mismatch'
  env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C \
    MON_CSR_PATH="$mon_request/monitor01.csr" MON_CSR_SHA256="$MON_CSR_SHA" \
    MON_LEAF_PROFILE="$mon_root/pki/monitor01-leaf.ext" \
    MON_LEAF_PATH="$MON_OUTPUT" MON_LEAF_DAYS="$mon_days" \
    /bin/bash --noprofile --norc -c "$mon_block"
}

main() {
  local mon_root mon_request='' mon_execute=no mon_days mon_confirm
  mon_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
  while (( $# )); do
    case "$1" in
      --execute) mon_execute=yes; shift ;;
      --request) (( $# >= 2 )) || stop '--request needs an absolute directory'; mon_request=$2; shift 2 ;;
      --help|-h) printf 'Usage: bash ca-start [--execute] [--request ABSOLUTE_DIRECTORY]\n'; return ;;
      *) stop 'Unknown argument' ;;
    esac
  done
  mon_request=${mon_request:-$mon_root/inputs/monitor01}
  if [[ "$mon_execute" == no ]]; then
    printf 'PLAN_ONLY\nHOST=ca01\nREQUEST=%s\nOUTPUT=%s\nNo CA operation executed. Add --execute on the ca01 root terminal.\n' "$mon_request" "$MON_OUTPUT"
    return
  fi
  export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C
  unset BASH_ENV ENV OPENSSL_CONF OPENSSL_CONF_INCLUDE OPENSSL_MODULES OPENSSL_ENGINES RANDFILE
  trap 'printf "STOP: operation failed; CA files may contain partial changes. Do not delete or reissue.\n" >&2' ERR
  umask 077
  identity
  safe_file "$mon_root/tools/pki/monitor01-ca-console.sh"
  lock_console
  check_request "$mon_request" "$mon_root"
  printf 'UTC: '; date -u '+%Y-%m-%d %H:%M:%S %Z'
  printf 'KST: '; TZ=Asia/Seoul date '+%Y-%m-%d %H:%M:%S %Z'
  read -r -p 'Leaf validity days selected for this request (no default): ' mon_days
  valid_days "$mon_days" || stop 'Days must be 1..9999, with no leading zero'
  printf 'The helper lock does not block other OpenSSL sessions.\n'
  read -r -p 'Clock correct? Type GO: ' mon_confirm
  [[ "$mon_confirm" == GO ]] || stop 'Clock was not confirmed'
  open_ca
  check_ca_state
  prepare_output
  sign_request "$mon_request" "$mon_root" "$mon_days"
  printf 'CA_SIGN_AND_VERIFY=PASS\nPUBLIC_LEAF=%s\nPUBLIC_ROOT=%s/certs/fds-root-ca.crt\nTLS_DEPLOYMENT=NOT_EXECUTED\n' "$MON_OUTPUT" "$MON_CA_DIR"
  printf 'CA volume remains open. Use the existing CA closing procedure after public-file return.\n'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
