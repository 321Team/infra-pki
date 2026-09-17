# 공개 Trust Bundle 등록 기준

현재 실제 인증서 파일 없음. 승인된 공개 CA 인증서만 등록한다. PEM은 CERTIFICATE 블록만 허용하며 PRIVATE KEY/암호화 key/PKCS12·실제 Secret을 포함하지 않는다. 확장자나 Private 저장소만으로 안전성을 판정하지 않는다.

자산 ID·승인 근거·발급자·serial·유효기간·SHA256 fingerprint·소비자·교체/폐기 상태를 대응 기록으로 연결한다. 공개 인증서의 hash 일치는 무결성이며 신뢰 승인이나 Runtime 성공이 아니다. 잘못된 Root trust 등록은 차단사항이다.
