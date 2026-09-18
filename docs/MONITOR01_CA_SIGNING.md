# monitor01 공개 CSR 서명·반환 절차 후보

상태: **PR의 코드·프로파일과 함께 검토할 실행안**. 현재 CA 서명·서버 적용은 미실행이다. 검토·병합된 소스와 생성된 공개 CSR을 사용하며, 기존 CA를 초기화하거나 새 Root를 만들지 않는다.

## 기존 자산과 권한

| 항목 | 기존 실행 기록에서 확인한 값 |
|---|---|
| 호스트 / 로그인 | `ca01` / `server01_ca01` |
| 실행 권한 | 기존 root 관리 셸. CA 볼륨은 root:root 0700, 키·인증서·대장·serial은 root:root 0600으로 기록됨 |
| CA 작업 디렉터리 | `/mnt/fds-ca/fds-project-root-ca-2026-replacement` |
| 서명 설정 / 공개 Root | `root-ca.cnf` / `certs/fds-root-ca.crt` |
| Root SHA256 인증서 지문 | `6a75baf4dbe03ef24cce944e616384d318f7ca919cd7bd914624b4cebac06b10` |
| 공개 Root PEM 파일 SHA256 | `20ddfa5e92c346aaf46fc30179fbc0b069e256effd2615a9f4308a8fe719053f` |

근거: [기존 CA 자산·공개 인계 기록](https://github.com/321Team/infra-cicd/blob/ee039707db0a7ae980305f65ffb741d46b149015/docs/implementation-state-20260915.md#ca-자산과-공개-인계), [구현 설정](https://github.com/321Team/infra-cicd/blob/ee039707db0a7ae980305f65ffb741d46b149015/config/p1-cicd-01.json), [현장 권한·발급 기록](https://github.com/321Team/fds-project-baseline/issues/16). 과거 serial `1001`은 현재 값으로 고정하지 않는다. 기존 볼륨·대장·키 소유권을 변경하지 않는다.

## 이번 요청에 연결할 입력

- monitor01에서 공개 내보내기로 받은 CSR·receipt·SHA256SUMS와 외부 archive SHA를 확인한다. **개인키는 monitor01에 남긴다.**
- `MON_CSR_PATH`: 검증한 CSR의 CA 측 절대 경로, `MON_CSR_SHA256`: 해당 공개 CSR의 검증된 SHA256.
- `MON_LEAF_PROFILE`: 검토·병합된 `pki/monitor01-leaf.ext`의 CA 측 절대 경로.
- `MON_LEAF_PATH`: 이번 요청 전용, 아직 존재하지 않는 출력 파일의 절대 경로. 부모는 root가 관리하는 기존 요청 디렉터리다.
- `MON_LEAF_DAYS`: 이번 monitor01 요청에서 Lead가 선택한 일수. 기존 CA의 `default_days=365`는 자동 적용하지 않는다. 이 입력은 CSR 생성에는 필요하지 않으며 별도 독립 승인 단계를 추가하는 것이 아니다.

CA 자산 기록에서 동일 CSR의 기존 발급 여부를 먼저 확인한다. 이미 서명됐다면 그 공개 Leaf를 검증·재전달하며, 출력 파일 이름만 바꿔 재발급하지 않는다. 이번 도구의 요청 식별자는 receipt의 전체 `csr_sha256`이다. 이 값과 발급 serial을 기존 자산 기록에 연결한다.

## CA 측 실행안

`ca01`의 기존 root 관리 셸에서 위 입력을 지정한 뒤 사용한다. 보호 볼륨 해제·마운트는 기존 운영 절차를 따르며 암호를 명령 인자·대화·로그에 넣지 않는다. 프로파일 SHA가 다르면 먼저 해당 변경의 검토 근거를 확인한다.

```bash
(
set -euo pipefail
[[ "$(hostname -s)" == ca01 && "$(id -u)" == 0 ]]
: "${MON_CSR_PATH:?검증된 CSR 절대 경로 필요}"
: "${MON_CSR_SHA256:?검증된 CSR SHA256 필요}"
: "${MON_LEAF_PROFILE:?승인된 Leaf 프로파일 절대 경로 필요}"
: "${MON_LEAF_PATH:?이번 요청의 신규 Leaf 절대 경로 필요}"
: "${MON_LEAF_DAYS:?이번 요청의 유효 일수 필요}"
[[ "$MON_CSR_PATH" == /* && "$MON_LEAF_PROFILE" == /* && "$MON_LEAF_PATH" == /* ]]
[[ "$MON_CSR_SHA256" =~ ^[0-9a-f]{64}$ ]]
[[ "$MON_LEAF_DAYS" =~ ^[1-9][0-9]{0,3}$ ]]
[[ -f "$MON_CSR_PATH" && ! -L "$MON_CSR_PATH" ]]
[[ -f "$MON_LEAF_PROFILE" && ! -L "$MON_LEAF_PROFILE" ]]
[[ ! -e "$MON_LEAF_PATH" && ! -L "$MON_LEAF_PATH" ]]
[[ "$(sha256sum "$MON_CSR_PATH" | cut -d' ' -f1)" == "$MON_CSR_SHA256" ]]
[[ "$(sha256sum "$MON_LEAF_PROFILE" | cut -d' ' -f1)" == \
   793962aab657fc833219aa020ee50f841f4ef4aeda08499815f2f1d51d614448 ]]

cd /mnt/fds-ca/fds-project-root-ca-2026-replacement
MON_ROOT_FP="$(openssl x509 -in certs/fds-root-ca.crt -noout -fingerprint -sha256 |
  cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
[[ "$MON_ROOT_FP" == 6a75baf4dbe03ef24cce944e616384d318f7ca919cd7bd914624b4cebac06b10 ]]
openssl x509 -in certs/fds-root-ca.crt -noout -checkend "$((MON_LEAF_DAYS * 86400))"
MON_CSR_VERIFY="$(LC_ALL=C openssl req -in "$MON_CSR_PATH" -verify -noout 2>&1)"
case "$MON_CSR_VERIFY" in
  'Certificate request self-signature verify OK'|'verify OK') ;;
  *) printf '%s\n' 'STOP: CSR signature verification did not confirm success' >&2; exit 1 ;;
esac
umask 077
openssl ca -config root-ca.cnf -notext \
  -days "$MON_LEAF_DAYS" \
  -extfile "$MON_LEAF_PROFILE" -extensions monitor01_leaf \
  -in "$MON_CSR_PATH" -out "$MON_LEAF_PATH"
openssl verify -x509_strict -CAfile certs/fds-root-ca.crt \
  -purpose sslserver -verify_ip 10.250.10.30 "$MON_LEAF_PATH"
openssl x509 -in "$MON_LEAF_PATH" -noout \
  -subject -issuer -serial -dates -fingerprint -sha256
)
```

`openssl ca`의 최종 서명/대장 반영 확인은 기존 CA 발급 동작이다. 실패하면 원본 오류와 기존 대장을 확인하고 중단한다. `index.txt`, `serial`, `newcerts`를 초기화하거나 Leaf 파일을 지워 재시도하지 않는다. 이미 반영된 서명은 파일 삭제로 취소되지 않는다.

## 공개 반환과 monitor01 검증

반환 목록은 **CSR·Leaf·Root 공개 인증서·공개 영수증·체크섬**으로 한정한다. CA 디렉터리 전체를 압축하지 않는다. 영수증에는 요청 ID, CSR SHA, 프로파일 SHA, Root 지문, Leaf serial·유효기간·지문, 실행자·UTC/KST 시각과 결과를 기록한다.

monitor01에서 반환물 무결성과 Root 지문을 확인한 뒤 체인·IP·서버 용도를 검증하고, CSR/Leaf/기존 로컬 키의 **공개키**가 같은지 비교한다. 개인키 파일은 읽기 권한이 있는 현지 OpenSSL만 사용하며 외부로 전달하지 않는다. 다른 키를 새로 만들어 맞추지 않는다. 키 불일치·미승인 Root·잘못된 SAN·만료면 배포를 중단한다.

반환된 공개 파일의 실제 절대 경로를 `MON_RETURNED_ROOT`, `MON_RETURNED_LEAF`에 지정하고 monitor01의 기존 계정에서 다음 읽기 전용 검사를 수행한다.

```bash
(
set -euo pipefail
[[ "$(hostname -s)" == monitor01 ]]
: "${MON_RETURNED_ROOT:?반환 Root 공개 인증서 경로 필요}"
: "${MON_RETURNED_LEAF:?반환 Leaf 공개 인증서 경로 필요}"
MON_ROOT_FP="$(openssl x509 -in "$MON_RETURNED_ROOT" -noout -fingerprint -sha256 |
  cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
[[ "$MON_ROOT_FP" == 6a75baf4dbe03ef24cce944e616384d318f7ca919cd7bd914624b4cebac06b10 ]]
openssl verify -x509_strict -CAfile "$MON_RETURNED_ROOT" \
  -purpose sslserver -verify_ip 10.250.10.30 "$MON_RETURNED_LEAF"
sudo -v
MON_KEY_PUBLIC_SHA="$(sudo -n openssl pkey \
  -in /etc/fds/pki/monitor01/request/monitor01.key -pubout -outform DER |
  sha256sum | cut -d' ' -f1)"
MON_CSR_PUBLIC_SHA="$(sudo -n openssl req \
  -in /etc/fds/pki/monitor01/request/monitor01.csr -pubkey -noout |
  openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)"
MON_LEAF_PUBLIC_SHA="$(openssl x509 -in "$MON_RETURNED_LEAF" -pubkey -noout |
  openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)"
[[ "$MON_KEY_PUBLIC_SHA" == "$MON_CSR_PUBLIC_SHA" && \
   "$MON_KEY_PUBLIC_SHA" == "$MON_LEAF_PUBLIC_SHA" ]]
printf '%s\n' 'PUBLIC_KEY_MATCH=PASS' 'CHAIN_IP_SERVER_PURPOSE=PASS'
)
```

TLS 프록시 설치, localhost receiver 바인딩, 인증 Secret, 허용 Remote Write 경로, TLS1.2 이상 및 긍정·부정 시험은 MON 배포 소스에서 이어간다. 서명 성공만으로 IF-06B 또는 ICR-AC12/16을 PASS로 변경하지 않는다. 신규 CA/키/인증서의 실제 서명·검증 결과가 생기기 전까지 이 문서는 실행안이다.
