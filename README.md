# HYRAM GOLF — 회원 인증 API (개발 초안)

Cloudflare Workers + D1 기반 회원 인증 백엔드. 운영 사이트 배포 전 별도 스테이징 검증 필요.

## 설정
1. Cloudflare D1 데이터베이스 생성: `wrangler d1 create hyram-golf-auth`
2. 출력된 database_id를 wrangler.toml에 입력
3. `npm install`
4. `npx wrangler d1 migrations apply hyram-golf-auth --local`
5. `npm run dev`

운영 배포는 승인 및 별도 환경설정 후 진행. 프런트엔드 연동과 비밀번호 재설정 이메일은 후속 작업.

## API
- POST /api/auth/register {email,password,name}
- POST /api/auth/login {email,password}
- GET /api/auth/me
- POST /api/auth/logout

인증 쿠키는 HttpOnly, Secure, SameSite=Lax. 비밀번호 PBKDF2-SHA256 해시. 모든 DB 쿼리 파라미터 바인딩.
