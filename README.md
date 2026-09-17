# infra-pki

Private CA/PKI 정책, 인증서 프로파일, 공개 trust bundle/fingerprint, 발급·갱신·폐기·복구 절차를 관리한다. **개인키·비밀번호·토큰·실제 Secret은 절대 저장하지 않는다.**

**상태: infra-cicd에 병합된 PKI 소스와 기존 Runbook의 이관 PR. 새 CA 발급·재발급·신뢰 변경 승인이 아니다.**

| 경로 | 역할 |
|---|---|
| `pki/` | 승인 이력이 있는 Root/Harbor CSR/Leaf profile, 도구 호환 경로 유지 |
| `tools/pki/` | Harbor-local CSR 생성 도구와 안전성 unit tests |
| `references/infra-cicd/` | 원본 Runbook·역할·작성 당시 검증 기록. 상태 문구는 과거 이력 |
| `runbooks/issuance-rotation.md` | 현재 진입 조건·발급/갱신·복구 책임 경계 |
| `trust-bundles/`, `fingerprints/` | 공개 자료 등록 기준만 준비; 실제 인증서·지문은 이번에 만들거나 복사하지 않음 |
| `docs/POLICY.md`, `docs/MIGRATION.md` | 운영 정책, 출처 및 전환 조건 |

CA 관리·서명·Runner trust는 이권욱, Harbor 키·CSR·설치·복구와 Worker 연계는 이하영의 기존 역할을 따른다. ca01 VM/계정/디스크 준비는 infra-ansible, Harbor 서비스와 Robot은 해당 저장소, 배포 Runner는 infra-cicd가 소유한다.

Root CA 개인키와 서명 DB는 승인된 오프라인 암호화 CA 환경에 남긴다. 서버 leaf 개인키는 해당 서버 보호 영역에만 둔다. PKI Git 저장소가 Private여도 키 보관 장소가 되지 않는다. 기존 Runbook의 최초 발급 명령을 현재 자산 확인 없이 재실행하지 않는다.

## 정본에 따른 운영 결정

[운영 정책](docs/POLICY.md)과 [정본 대응·책임 경계](docs/CANONICAL_POLICY.md)를 적용한다. Private/main을 유지하고, 이번 소스 이관은 로컬 검증 증적과 독립 검토 후 수동 병합으로 판단한다. Actions 활성화는 이관의 새 필수 AC가 아니며 CI 미실행은 NOT RUN으로 기록한다. 중앙 Delivery는 기존 infra-cicd 전용 Runner 경계를 유지한다.
