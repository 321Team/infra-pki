# PKI 발급·갱신·복구 진입 기준

정책/Source 인계용 문서다. 서버 명령을 이번 PR에서 실행하지 않는다. 실행자는 CA 관리 이권욱, Harbor 적용 이하영이며 승인된 source SHA·자산 ID·작업창·복구안을 먼저 확정한다.

## 기존 자산 확인

원본 [infra-cicd PR #2](https://github.com/321Team/infra-cicd/pull/2)의 최신 기록은 CA 발급·백업 진행을 설명하므로 참고 Runbook의 `NOT_EXECUTED`를 현재 사실로 되돌리지 않는다. 발급된 키/CSR을 다시 만들지 않는다. 실제 승인 Root 지문, 요청 ID, CSR/Leaf 공개키, serial·유효기간·배포 소비자·폐기/복구 상태는 원본 실행 증적과 대조해야 한다.

## 승인된 방식

- 새 Root 결정과 ca01/server01 배치 기록을 따른다. CA 자산·키·DB는 별도 오프라인 암호화 볼륨과 보호 백업에 둔다. VM 준비/계정/디스크는 infra-ansible과 연결한다.
- `pki/root-ca.cnf`, `pki/harbor-csr.cnf`, `pki/harbor-leaf.ext`는 그대로 이관했다. RSA4096 Root/1825일, RSA3072 Harbor/365일, 30일 전 갱신이라는 기존 운영값은 원본 결정과 발급 전 검토를 따른다. 다른 서비스에 Harbor SAN을 재사용하지 않는다.
- `tools/pki/create_harbor_csr.py`는 Linux harbor01의 기존 계정·IP·보호 경로 guard를 유지한다. `--apply`는 서버의 새 key/CSR을 만드는 변경이므로 승인된 새 요청에만 사용한다. 이관·단위시험이 `--apply` 허가가 아니다.
- 공개 CSR·Leaf·CA·fingerprint·영수증만 전달한다. 키·암호·서명 DB를 Git, Runner, 대화, 증적 압축물에 넣지 않는다.

## 갱신/전환 순서와 중단조건

1. 승인 요청·SAN·키 길이·CSR 서명·현재 CA 자산·잔여 유효기간·백업을 검토한다. 불일치/미확인 또는 이미 발급된 요청의 중복 생성 위험이면 중단한다.
2. 서명자는 요청의 임의 확장을 복사하지 않고 승인 profile로 CA:FALSE·serverAuth·SAN을 강제한다. 실패 시 index/serial/newcerts를 초기화하지 않고 기존 발급 기록부터 조사한다.
3. 승인 자산의 Root 지문과 반환물의 지문을 대조한다. 받은 파일의 해시만으로 신뢰를 새로 승인하지 않는다. Leaf/CSR/서버 key의 공개키 일치·체인·SAN·만료를 검증한다.
4. 소비자 trust와 서비스 전환은 각 도메인의 승인 Runbook으로 수행한다. strict TLS와 필요한 Push/Pull·negative test·회귀를 확인한다. TLS 검증 우회로 통과시키지 않는다.
5. 구 CA 폐기 결정이 적용된 경우 구 Root를 재신뢰시키는 rollback을 사용하지 않는다. 승인된 유효 체인으로 이전 서비스 구성을 복구할 수 없으면 중단 상태에서 원인을 해결한다.
6. 증적은 host/account/time/source SHA/command/rc/log/hash와 원본 수신 경로를 남긴다. 승인된 소비자 전환과 폐기 완료 전에는 전체 PKI 인수를 선언하지 않는다.

원본 상세 절차는 [이관된 당시 Runbook](../references/infra-cicd/docs/harbor-formalization.md)을 참고하되 그 문서의 과거 상태·키트 경로를 현장 현재값으로 가정하지 않는다. 현재 CSR 요청/발급물·실행 키트·소비자 source pin이 확정된 후 별도 실행 검토한다.
