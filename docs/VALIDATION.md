# 이관 검증 기록

작성 시각: 2026-09-17T16:21:01.200510+09:00 (KST). 대상: 이 PR의 prepared source. 코드/파일 출처와 해시는 MIGRATION_MANIFEST.json 기준.

| 단계 | 결과 | 범위 |
|---|---|---|
| STATIC | PASS | 8개 이관 파일의 destination Git blob/SHA256 대조, UTF-8·Python AST·해당 YAML/JSON·신규 문서 상대 링크 검사 |
| 비밀정보 제한 패턴 검사 | 0건 검출 | PEM private-key header, GitHub token, Discord webhook credential, AWS access-key pattern. 완전한 secret audit을 의미하지 않음 |
| MOCK/UNIT | 아래 기록 | 실제 서비스 인수 아님 |
| CI | 문서 작성 시 NOT RUN | 새 source-validation workflow 준비. 이후 실제 PR Checks의 commit/run/attempt로 판정 |
| RUNTIME | NOT RUN | 서버·클러스터·DB·CA·Harbor 변경 및 배포 없음 |
| REVIEW/MERGE/PUBLICATION | PENDING / NOT_DONE / NOT_DONE | 독립 승인·병합·발행 전 |

- Linux 전용 pwd/UID 안전성 unit tests는 이 Windows 로컬에서 미실행. GitHub 제공 ubuntu-24.04의 새 소스 CI에서 원본 11개 시험을 실행하도록 준비했다. 원본 infra-cicd PR #2에서 확인된 과거 PASS와 신규 저장소 CI 결과는 구분한다. 실제 키·CSR·CA 발급을 하지 않는다.

## 새 CI의 범위

GitHub 제공 ubuntu-24.04, contents:read, checkout credential 비보존, repo 일치 guard와 timeout을 사용한다. pin은 infra-cicd의 검증된 checkout `d23441a48e516b6c34aea4fa41551a30e30af803`를 이어받았다. self-hosted Runner·Secret·인증서·배포 명령을 쓰지 않는다.

실행 항목은 UTF-8/AST/YAML/JSON·제한 secret pattern, 앱 저장소의 기존 unit/contract smoke tests, PKI의 원본 CSR safety unit tests, Monitoring의 shell syntax다. 과거 CI를 복제한 것이 아니며 source CI의 성공을 Runtime 성공으로 표현하지 않는다.

초기 이관 hash 검증은 `python tools/verify_migration.py`로 수행한다. 이후 구현 변경을 금지하는 영구 CI gate로 연결하지 않는다. source verifier는 실제 파일을 읽고 검사할 뿐 이관된 실행 도구/시연 스크립트를 실행하지 않는다.

원본 89개 중 88개는 byte-preserved, Grafana 참고본 1개만 기본 암호 placeholder 치환이다(세 저장소 합계). 본 저장소 해당 목록/차이는 manifest에서 확인한다. Runtime 증적·공개 CA 신뢰·source cutover는 별도다.

## 2026-09-17 정본 기준 정책 보완

이번 후속 변경은 POLICY·정본 대응표·README·PR 양식·이 검증 기록의 문서 5개에 한정한다. 이관된 코드/프로파일/테스트/Workflow/manifest는 변경하지 않는다. 이전 단위시험 결과를 새 CI 결과로 표시하지 않는다. 변경 문서 구문·상대 링크·이관 hash 보존과 원격 blob/mode 대조 결과는 이 후속 commit의 PR 본문에 기록한다.

세 신규 저장소 Actions가 조직 정책으로 비활성인 점을 2026-09-17 16:27 KST 확인했다. 정본 RELEASE_POLICY §6의 보상 통제를 이번 운영에 적용하며, CI 활성화 자체를 소스 이관 선행조건으로 추가하지 않는다. 실제 CI=NOT RUN, Runtime=NOT RUN, 독립 REVIEW=PENDING이다. 제한 수용·소스 병합·소비자 전환은 각각 별도 기록한다.

### PKI 원본 CI 이력과 동일성

[원본 Run 34962038714 / Attempt 1](https://github.com/321Team/infra-cicd/actions/runs/34962038714/attempts/1), 원본 SHA `ffaa764623c5941b14fe12384e9ba5629bd60a6f`, 2026-09-15 20:12 KST는 success다. Job `104357653976`의 검증 step success를 재확인했다. [P1-CICD-01 #16](https://github.com/321Team/fds-project-baseline/issues/16)에 수집기17 + CSR11 = 28건 OK로 기록되어 있다. 이는 원본 Linux 시험 이력이며 신규 저장소의 재실행이 아니다.

그 run의 tree와 현재 이관본에서 `pki/root-ca.cnf`, `pki/harbor-csr.cnf`, `pki/harbor-leaf.ext`, `tools/pki/create_harbor_csr.py`, `tools/pki/test_create_harbor_csr.py` 5개 Git blob·mode가 동일하다. 상대 경로도 유지한다. 신규 저장소 Linux CSR11은 여전히 NOT RUN이다. 독립 검토자는 동일한 snapshot 이관 범위의 제한 수용 여부를 명시하고, 로직/프로파일/의존성/실행 경로 변경 시 해당 시험을 다시 요구한다. 이 기록으로 발급/Trust/Runtime을 승인하지 않는다.

## 2026-09-18 승인 절차 변경

[사용자 변경결정](https://github.com/321Team/fds-project-baseline/blob/38f682141c279807050c5b1ea1b4e2b58ee22d63/governance/REVIEW_AUTHORITY_POLICY.md)에 따라 독립 리뷰는 코드 병합에 한정한다. 이번 보완은 정책·대응표·README·PR 양식·이 검증 설명의 Markdown 5개 변경이며, 기존 코드·Workflow·이관 manifest와 시험 이력은 보존한다. 이관 PR 전체에는 코드가 포함되므로 독립 리뷰가 계속 필요하다. 코드 외 Runtime·증적 수용·인수·종결은 해당 Lead가 결정한다. 이번 문서 보완으로 CI/Runtime을 새로 수행하거나 과거 검증 상태를 상향하지 않는다.
