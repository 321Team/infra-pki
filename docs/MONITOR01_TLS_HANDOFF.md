# monitor01 TLS 인계 후보

상태: **소스 후보 / 운영 발급·배포 미실행**. 인증서 profile은 실행 설정이므로 [저장소 정책](POLICY.md)에 따라 해당 PR의 최신 HEAD에 대한 독립 리뷰와 병합 후 Lead가 운영 실행을 판단한다. 동일 승인 소스의 발급·배포·증적 수용마다 별도 독립 승인을 반복하지 않는다.

## 확정 범위

근거는 [발행 정본 v3.1.19](https://github.com/321Team/fds-project-baseline/tree/966fc5365874b1d259a9810fc876b57c3bfa0e08)의 §11.4와 IF-06B다.

| 항목 | 이번 후보의 범위 |
|---|---|
| 수신 주소 | monitor01 `10.250.10.30:443` |
| 인증서 | 기존 프로젝트 Private CA가 서명하는 monitor01 전용 서버 Leaf |
| SAN | CSR·Leaf 모두 IP `10.250.10.30` 하나만 포함 |
| Subject | `C=KR, O=FDS, OU=Monitoring, CN=monitor01`; 식별용 구현 제안이며 DNS 접속 이름 승인이 아님 |
| 개인키 | monitor01에서 생성·보관, 외부로 반출하지 않음 |
| 프록시 | TLS 프록시가 Remote Write 경로만 localhost 수신기로 전달 |
| 변경 파일 | `pki/monitor01-csr.cnf`, `pki/monitor01-leaf.ext`, `tools/pki/create_monitor01_csr.py`, 격리 시험 및 이 문서 |

Leaf 확장은 `CA:FALSE`, 서버 인증 용도, IP SAN을 강제한다. `digitalSignature,keyEncipherment`는 기존 Harbor profile 형식과 같은 **RSA profile 제안**이며 모든 서비스의 키 알고리즘 정책을 새로 정한 것이 아니다. 요청 생성 도구는 RSA3072를 이번 구현값으로 제안하며, Leaf 유효기간은 운영 요청에서 기존 CA 정책 및 Lead 판단에 맞춰 확정한다. Harbor의 SAN·365일 유효기간을 monitor01에 자동 승계하지 않는다. Root 생성·교체 및 서명·배포 자동화는 포함하지 않는다. `tools/pki/create_monitor01_csr.py`는 승인 이후 monitor01에서 사용할 로컬 요청 생성·재사용 도구다.

## 현재 관측과 남은 입력

2026-09-18 사용자 제공 출력에서 monitor01 주소는 `10.250.10.30/24`, `9090` 소켓의 소유자는 `cockpit.socket`이고 enabled다. 앞선 출력에서 `443` Listener는 보이지 않았다. 조회한 Prometheus/Blackbox/프록시 unit은 확인되지 않았고 현재 사용자 및 root의 Podman 목록은 비어 있었다. 임의 바이너리, 다른 사용자 컨테이너, 다른 관리 방식까지 미설치라고 확정한 결과는 아니다.

Cockpit을 Prometheus로 오인하지 않는다. 정본 §6.6의 K8S 6대 Cockpit 기준을 monitor01에 확대하지 않는다. 이 후보는 Cockpit 중지나 9090 재사용을 요구하지 않으며 localhost 수신기 포트를 지정하지 않는다.

| 인계 대상 | 담당 및 필요한 확인 |
|---|---|
| 모니터링 구축 | MON Lead 이재환: receiver/프록시 구현·버전 또는 승인 Image Digest, localhost 주소·포트, Remote Write 경로, 인증 방식과 Secret 참조 이름·경로 확정 |
| PKI 지원 | 이권욱: 기존 승인 Root 공개 지문·자산 ID 확인, 중복 요청 여부와 공개 CSR 검사, 승인 Leaf 발급·공개 반환물 검증 지원 |
| K8S·보안 연동 | 이하영 및 MON Lead: 송신 Prometheus 설정과 CA trust, 인증 참조, payload allowlist, 실제 패킷 source 및 필요한 허용 정책 확인 |

인증 값·개인키·토큰·CA 서명 DB는 인계하지 않는다. 위 미확정 입력이 있다고 이미 확정된 IP SAN·기존 Root 결정을 재승인할 필요는 없다. MON 구현을 PKI Support가 중복 구축하지 않는다.

## 요청 및 반환물 검사

1. 기존 monitor01 요청·CSR·Leaf가 있는지 자산 기록과 대조한다. 존재하면 새 키/CSR을 덮어쓰거나 중복 발급하지 않는다. 실제 키 생성·서명은 승인된 소스와 운영 요청으로 수행한다.
2. CSR 서명·정확한 IP SAN·공개키를 확인한다. 서명자는 CSR 확장을 무조건 복사하지 않고 `monitor01_leaf` 확장을 명시한다. 실제 CA 키·서명 DB에는 격리 시험용 생성 명령을 사용하지 않는다.
3. 반환 Leaf는 기존 승인 Root 지문과 연결된 체인으로 검증한다. CSR·Leaf·서버 로컬 키의 공개키 일치, `CA:FALSE`, `serverAuth`, 정확한 IP SAN, serial·유효기간을 확인한다. 공개 반환물 해시 일치만으로 새 Root를 신뢰하지 않는다.
4. MON Lead가 자신의 배포 소스에서 프록시 인증·경로 제한·localhost 바인딩을 구현하고 K8S 송신 측이 승인 Root를 신뢰하도록 연결한다. TLS 검증 우회 없이 IF-06B 양방향 경로·인증·payload·허용/차단 시험을 남긴다. 프로파일 시험 성공은 이 Runtime 인수가 아니다.

아래는 **기존 파일에 대한 읽기 전용 검사 예시**다. `MON_CSR`, `MON_LEAF`, `MON_ROOT`는 검증 대상 공개 파일의 실제 경로로 실행자가 지정한다. Root는 승인 지문 대조를 먼저 완료하며 필요하면 승인 중간 체인을 별도 제공한다.

```bash
openssl req -in "$MON_CSR" -verify -noout
openssl req -in "$MON_CSR" -text -noout
openssl x509 -in "$MON_LEAF" -text -noout
openssl verify -CAfile "$MON_ROOT" -purpose sslserver \
  -verify_ip 10.250.10.30 "$MON_LEAF"
```

## 격리 검증

```bash
python3 -I -B -m unittest discover -s tools/pki -p 'test_monitor01_profiles.py' -v
```

시험은 임시 디렉터리에서 가상의 CA·Leaf 키만 생성하고 종료 시 삭제한다. 실제 CA, 서버 개인키, 네트워크, 서비스에 접근하지 않는다. 시험용 RSA2048·1일 유효기간·serial 1은 재현용 fixture이며 운영 정책이 아니다. OpenSSL 부재로 SKIP되면 PASS로 기록하지 않는다.

검증 범위는 CSR 서명 및 IP SAN, Leaf 확장과 IP SAN, CSR/Leaf/로컬 키의 공개키 일치, 올바른 IP와 서버 용도 체인 검증, 잘못된 IP 거부, 클라이언트 인증 용도 거부다. 실제 서버 Runtime·배포·인증·프로토콜 검증과 CI 결과는 별도로 기록한다.

OpenSSL 문법 및 검증 근거: [X.509 확장 설정](https://docs.openssl.org/3.5/man5/x509v3_config/), [체인 및 IP·용도 검증](https://docs.openssl.org/3.5/man1/openssl-verify/).

## 병합 후 monitor01 실행

이하 명령은 **최신 후보 HEAD의 독립 리뷰·병합 이후**, 배포 묶음의 SHA256와 내부 파일 검증을 마친 디렉터리에서 사용한다. 현재 문서 자체가 운영 실행 승인은 아니다. MON Lead의 실행 판단은 기존 티켓에 한 번 기록하면 된다.

```bash
python3 -I -B tools/pki/create_monitor01_csr.py
sudo -v
sudo -n /usr/bin/python3 -I -B tools/pki/create_monitor01_csr.py --apply
```

실행 계정은 `server01_monitor`, 호스트는 `monitor01`, 기대 주소는 ens160의 `10.250.10.30`이다. 기본 실행은 `PLAN_ONLY`이며 파일을 만들지 않는다. `--apply`는 root 소유 `/etc/fds/pki/monitor01/request`(0700)에 `monitor01.key`, `monitor01.csr`, `request.json`(각 0600)을 생성한다. 이 경로는 이번 구현 선택이며 정본이 강제한 경로가 아니다.

완성된 기존 요청이 있으면 CSR 서명·SAN·RSA3072 공개키 일치·profile SHA256·요청 메타데이터를 대조하고 같은 CSR을 `REUSED`로 내보낸다. 부분 생성, 불일치, 심볼릭 링크, 느슨한 권한, 미지 파일은 그대로 보존하고 `STOP`한다. 자동 삭제·덮어쓰기·개인키 백업 복사는 없다. 같은 디렉터리의 root 소유 잠금 파일로 동시 요청 생성을 막는다. 처음 생성된 키·CSR을 임의로 지워 재시도하지 않는다.

출력 `archive`·`sidecar`는 일반 계정 홈의 고유한 파일명이다. 필요하면 `--output-dir`에 해당 계정이 소유한 안전한 기존 절대 디렉터리를 지정한다. 내보내기 프로세스는 일반 계정 UID/GID로 권한을 낮춘 후 **공개 CSR, 공개 receipt, SHA256SUMS**만 압축한다. 개인키·CA 키·서명 DB는 읽어 내보내지 않는다. 개인키는 CSR 및 공개키 일치 검사에만 로컬에서 사용된다.

이번 요청은 receipt의 전체 `csr_sha256`으로 식별한다. 다시 내보낸 압축물의 파일명·외부 해시가 바뀌더라도 같은 CSR SHA이면 같은 키·요청이다. receipt의 `public_key_sha256`은 PEM 공개키 바이트의 SHA256이며, CA 반환 절차에서 비교하는 DER 공개키 해시와 표현 형식을 구분한다.

`CREATED` 또는 `REUSED`와 두 파일이 나오면 공개 묶음을 인계한다. CA 측 공개 지문·서명/반환 확인은 [MONITOR01_CA_SIGNING.md](MONITOR01_CA_SIGNING.md)로 이어간다. 출력을 얻지 못해도 protected 요청은 보존되므로 원인 해결 후 같은 도구로 재사용한다. 이 도구는 서비스 설치·재기동, 방화벽, Cockpit, 실제 TLS 연결을 변경하지 않는다.

추가 시험: `python3 -I -B -m unittest discover -s tools/pki -p 'test_*.py' -v`. 모의 identity/경로 보호 시험과 실제 임시 OpenSSL 요청 생성·재사용·공개 압축물 시험을 구분하며 실제 CA/monitor01 Runtime 성공으로 표시하지 않는다.
