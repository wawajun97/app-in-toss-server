# Heylocal Server

헤이로컬 앱 사용자를 Apps in Toss 인증과 연동하기 위한 Spring Boot 백엔드 서버입니다.

이 서버는 Toss OAuth 토큰 발급, 사용자 정보 조회, Firebase Custom Token 발급, 로그아웃 콜백 처리를 담당합니다.

## 기술 스택

| 구분 | 사용 기술 |
| --- | --- |
| Language | Java 17 |
| Framework | Spring Boot 3.5.4 |
| Build | Gradle |
| HTTP Client | Spring WebClient |
| Auth / External | Apps in Toss API, Firebase Admin SDK |
| Data 연동 | Supabase REST API, Firestore |
| Deploy | GitHub Actions, AWS EC2, Dockerfile |

## 주요 역할

- Apps in Toss OAuth API와 연동하여 access token / refresh token 발급 및 갱신
- Toss 사용자 정보 조회 후 AES-GCM 방식으로 암호화된 사용자 정보 복호화
- Firebase 사용자 조회 또는 생성 후 Firebase Custom Token 발급
- Toss 로그아웃 콜백 수신 시 Firebase, Supabase, Firestore 사용자 데이터 정리
- mTLS 인증서 기반 WebClient로 Toss API 호출

## 인증 흐름

```text
Client
  -> POST /toss-auth
  -> Heylocal Server
  -> Apps in Toss API: access token 발급
  -> Apps in Toss API: 사용자 정보 조회
  -> Heylocal Server: 사용자 정보 복호화
  -> Firebase Auth: 사용자 조회 또는 생성
  -> Client: Firebase Custom Token 반환
```

### 상세 처리 순서

1. 클라이언트가 Toss 인증 후 받은 `authorizationCode`를 서버로 전달합니다.
2. 서버는 mTLS 인증서가 적용된 WebClient로 Apps in Toss API에 토큰 발급을 요청합니다.
3. 발급받은 access token으로 Toss 사용자 정보를 조회합니다.
4. Toss에서 전달된 암호화 사용자 정보를 AES-GCM 방식으로 복호화합니다.
5. Firebase Auth에서 `userKey` 기반 사용자를 조회하고, 없으면 새로 생성합니다.
6. Firebase Custom Token을 생성해 클라이언트에 반환합니다.

## 로그아웃 콜백 흐름

```text
Apps in Toss
  -> POST /logout
  -> Firebase Auth 사용자 삭제
  -> Supabase 사용자 탈퇴 상태 업데이트
  -> Firestore fcmTokens / badgeCount 초기화
```

로그아웃 콜백은 Toss와의 연결 해제 이후 헤이로컬 서비스 내부 사용자 상태를 정리하기 위한 흐름입니다.

## 핵심 구현 포인트

### mTLS 기반 Toss API 호출

`TLSClientUtil`에서 Toss API 호출에 필요한 클라이언트 인증서와 private key를 읽어 `SslContext`를 구성합니다. 이후 Reactor Netty 기반 `WebClient`에 적용해 Apps in Toss API를 호출합니다.

### Firebase Custom Token 발급

`LoginService`는 Toss 사용자 정보에서 `userKey`를 추출해 Firebase 사용자 UID로 사용합니다. 기존 사용자가 있으면 재사용하고, 없으면 새로 생성한 뒤 Firebase Custom Token을 발급합니다.

### 사용자 정보 복호화

Toss에서 전달되는 사용자 정보 중 전화번호, 이메일 등은 AES-GCM 방식으로 암호화되어 있습니다. 서버는 `base64.encoded.aes.key` 설정값을 이용해 복호화한 뒤 Firebase 사용자 생성에 활용합니다.

### 로그아웃 후 사용자 데이터 정리

`/logout` 콜백에서는 Firebase Auth 사용자 삭제, Supabase 사용자 타입 변경, Firestore 푸시 토큰 및 배지 수 초기화를 순차적으로 처리합니다.