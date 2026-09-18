# ca01 텍스트 콘솔 실행 도구

`multi-user.target`에서 복사·붙여넣기를 사용할 수 없는 ca01에 맞춘 짧은 진입점이다. GUI·네트워크·클립보드 활성화나 Python 설치를 요구하지 않는다. 새 실행 코드는 이 PR의 독립 검토·병합 후 사용한다. 기존 PR #3의 서명 Bash 블록과 Leaf 프로파일은 변경하지 않는다.

## 입력과 실행

현재 공개 요청 `37fda6d9fb99f101bf213a8e6a070c3e6dce3ba5238b54f178d9c62c8ddd3fa1`만 처리한다. 다른 요청에 재사용할 때는 pin을 바꾸는 코드 검토가 필요하다. 새 CSR·개인키·Root를 생성하지 않는다.

배포 ISO에는 저장소의 `ca-start`, `tools/pki/monitor01-ca-console.sh`, `docs/MONITOR01_CA_SIGNING.md`, `pki/monitor01-leaf.ext`와 이미 검증된 공개 `inputs/monitor01/monitor01.csr`, `inputs/monitor01/receipt.json`을 같은 경로로 담는다. 배포자는 검토·병합된 commit, 파일별 SHA256, ISO SHA256을 함께 제공한다. 공개 요청 원본은 소스 저장소에 다시 커밋하지 않는다.

새 ISO의 예정 라벨은 `MONCA11`, 기존 마운트 경로는 `/mnt/mon01-csr`다. 배포 안내에서 해당 ISO의 승인·무결성을 확인한 후, 현재 root 콘솔에서 기존 ISO를 해제한다.

```bash
cd /mnt
umount mon01-csr
```

VMware 호스트에서 새 ISO로 교체한 후 입력한다.

```bash
mount -o ro,nodev,nosuid,noexec -L MONCA11 mon01-csr
bash mon01-csr/ca-start --execute
```

긴 UUID·해시·경로를 직접 타이핑하지 않는다. 옵션 없이 `bash mon01-csr/ca-start`만 실행하면 PLAN_ONLY다. 실행 화면은 ASCII이며 유효 일수에는 기본값이 없다. 표시된 시각이 실제 UTC/KST와 맞는지 확인하고 진행한다. 필요한 기존 암호는 cryptsetup/OpenSSL의 현지 입력창에만 입력한다. OpenSSL의 서명·대장 반영 확인은 기존 동작 그대로다.

## 실행 범위와 중단

- UID 0, 호스트 `ca01`, 대화형 TTY를 확인하고 요청·receipt·승인된 문서·프로파일의 해시를 검사한다. 일반 사용자 계정의 sudo 권한을 추가하거나 CA 권한을 완화하지 않는다.
- 알려진 UUID의 기존 LUKS 볼륨을 열고 `/mnt/fds-ca`에 마운트한다. 이미 열린 매핑·마운트는 실제 장치와 `rw,nodev,nosuid,noexec`를 확인해 재사용한다. 불일치는 중단하며 자동 재마운트·포맷은 없다.
- 기존 Root 지문과 발급 대장을 검사한다. 요청 출력이나 monitor01 발급 기록이 있으면 보존하고 중단한다. 실패한 파일을 지우거나 이름을 바꿔 재발급하지 않는다.
- `/run`의 잠금은 이 도구의 중복 실행만 막는다. 별도 OpenSSL 세션까지 잠그는 기능은 아니다.
- 승인된 문서의 첫 Bash 블록을 바이트 동일하게 추출해 실행한다. 정상 종료 시 공개 Leaf·Root의 경로를 출력한다. CA 발급 중 실패하면 파일·대장에 일부 변경이 남을 수 있으므로 자동 롤백이나 재시도는 하지 않는다.

공개 반환과 CA 볼륨 종료는 기존 절차로 이어간다. 이 도구는 USB 대상을 추정하거나 CA 디렉터리를 압축하지 않으며 monitor01 TLS 배포·AC 인수까지 수행했다고 표시하지 않는다. 기존 CSR 검증을 다시 사용자에게 수동으로 요구하지 않는다.

## 검증

```bash
bash -n ca-start tools/pki/monitor01-ca-console.sh
python3 -m unittest discover -s tools/pki -p 'test_*.py' -v
```

Python은 소스 테스트 환경에서만 사용하며 ca01 실행 의존성이 아니다. 모의 검증은 실제 CA 서명 성공을 대신하지 않는다.
