# 정본 대응과 저장소 책임

기준 확인: 2026-09-17 KST. 발행 정본 `docs-v3.1.18`, 승인 source `72599ae49342b0fb8dbd3d8ee60314afb9f907bb`. 이 문서는 정본을 새로 발행하거나 기존 Decision·AC를 변경하지 않는다.

| 정책 | 직접 근거 | 적용 성격 |
|---|---|---|
| Private, reviewed PR, 독립 Reviewer, 수동 merge, CI 미실행 표기 | [RELEASE_POLICY §1·§4·§5·§6](https://github.com/321Team/fds-project-baseline/blob/121fb744f0d816b3910a0bb07cf2bbe0d8883a16/governance/RELEASE_POLICY.md) | 정본의 보상 통제를 이번 신규 소스 운영에 적용 |
| Lead 구현 → Support 영향/보안/운영 검토 → 증적·승인 후 Done | [Baseline §3.4·§17](https://github.com/321Team/fds-project-baseline/blob/72599ae49342b0fb8dbd3d8ee60314afb9f907bb/baseline/FDS_Project_Implementation_Baseline_v3.1.18.md) | 기존 티켓 lifecycle/인수 조건 유지 |
| 기존 운영 담당과 정본 승인 역할 구분 | [Baseline §3](https://github.com/321Team/fds-project-baseline/blob/72599ae49342b0fb8dbd3d8ee60314afb9f907bb/baseline/FDS_Project_Implementation_Baseline_v3.1.18.md), [Identity Map](https://github.com/321Team/fds-project-baseline/blob/121fb744f0d816b3910a0bb07cf2bbe0d8883a16/governance/GITHUB_IDENTITY_MAP.md) | 기존 역할 유지, 권한 변경 없음 |
| 중앙 Delivery와 단순 소스 검증 분리 | [Baseline §5·§10](https://github.com/321Team/fds-project-baseline/blob/72599ae49342b0fb8dbd3d8ee60314afb9f907bb/baseline/FDS_Project_Implementation_Baseline_v3.1.18.md), [병합된 infra-cicd README/운영 기준](https://github.com/321Team/infra-cicd/blob/90f2f37d9e1ab77252b50e80bca339cfef48bd51/README.md) | Runner 접근 확대 없음 |
| 3개 저장소 이름, snapshot-copy, 폴더, 브랜치 접두어 | 이번 사용자 개설·정본 기준 정책·이관 요청 | 이번 운영 세칙, 정본의 원문 강제 사항으로 표시하지 않음 |

## 해당 저장소의 필수 경계

- 책임: D19 [#64](https://github.com/321Team/fds-project-baseline/issues/64), [Baseline §3.7·§11.4](https://github.com/321Team/fds-project-baseline/blob/72599ae49342b0fb8dbd3d8ee60314afb9f907bb/baseline/FDS_Project_Implementation_Baseline_v3.1.18.md), [병합된 CA/Harbor 역할 기록](https://github.com/321Team/infra-cicd/blob/90f2f37d9e1ab77252b50e80bca339cfef48bd51/docs/decisions/p1-cicd-01-roles.md). CA 관리/서명/Runner Trust는 이권욱, Harbor 키/CSR/설치와 Worker 연계는 이하영이다. D19 당시 승인 이력은 해당 Decision 원문 그대로 유지한다.
- 프로젝트 Private Root CA + 서비스별 Leaf + Consumer CA Trust, SAN, TLS1.2 이상, Positive/Negative·갱신·복구 검증을 유지한다. Harbor·edge01·monitor01의 서비스별 신뢰 범위를 구분하고 Harbor SAN을 다른 서비스에 재사용하지 않는다.
- 공개 CA/Leaf/CSR과 fingerprints는 비밀키가 없고 승인 자산·현재 유효성·지문·출처를 대조한 경우에만 별도 PR로 등록한다. Private 저장소도 Root/Leaf 개인키·암호·서명 DB·민감 백업의 보관소가 아니다. CA 개인키를 Runner/Actions Secrets에 제공하지 않는다.
- Root 자산은 승인된 오프라인 보호 CA 환경, 서비스 Leaf 키는 해당 서버 보호 경로에 둔다. VM/계정/디스크는 infra-ansible, 각 서버의 인증서 적용/복구는 해당 서비스 저장소 책임이다.
- Robot 설계/발급은 TLS와 병행할 수 있지만 실제 Harbor 로그인·Push/Pull과 완료 증적은 서버 인증서·Consumer CA Trust 적용 후다. 코드 이관·CSR unit 시험으로 이 Gate를 통과시키지 않는다.
- 기존 CA 발급·백업과 구 CA 폐기 결정은 최신 [P1-CICD-01 #16](https://github.com/321Team/fds-project-baseline/issues/16) 및 [infra-cicd PR #2](https://github.com/321Team/infra-cicd/pull/2) 기록을 따른다. 과거 NOT_EXECUTED runbook을 현재 미발급으로 해석하거나 최초 발급을 재실행하지 않는다.
- Root RSA4096/1825일·Harbor RSA3072/365일·30일 전 갱신은 이관 원본의 기존 구현값이다. 이를 모든 서비스에 대한 새 전사 PKI 표준으로 확대하지 않는다. profile/SAN/유효기간 변경은 기존 결정·자산·소비자 영향 검토를 거친다.
- [발급·갱신·복구 진입조건](../runbooks/issuance-rotation.md)을 확인하고 승인 source와 요청 ID를 고정한다. CA/키/Trust 변경·서버 적용은 이번 snapshot 이관의 범위 밖이다.

## 이관의 판정 범위

정본 AC의 값·담당·기한·상태를 변경하지 않는다. 초기 이관은 출처·무결성·의존성·비밀정보·적용 가능한 소스 검증과 독립 검토로 판단하며, 미실행 CI/Runtime은 각각 그대로 기록한다. 상세 Gate는 [운영 정책](POLICY.md)을 따른다.
