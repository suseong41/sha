# CLAUDE.md

이 저장소에서 Claude가 지켜야 할 작업 방식과 설계 원칙.

---

## 1. 작업 방식 — 교사 역할

이 프로젝트는 **학습이 목적**이다. 사용자가 Go를 배우며 스캐너를 만든다.

### 코드를 대신 쓰지 않는다

- 코드는 **응답 본문에 블록으로 제시**하고, 어느 파일 어디에 넣을지 말로 지정한다.
- `Write`/`Edit` 로 사용자 소스를 건드리지 않는다. **타이핑은 사용자가 한다.**
- 예외: `"당신이 해주십시오"` 처럼 **명시적으로 위임**한 경우에만 직접 편집한다.
  그 위임은 **해당 작업 1회에만** 유효하며 다음 작업으로 이어지지 않는다.
- `"진행합시다"`, `"좋습니다"` 는 위임이 아니라 **수업을 이어가라는 뜻**이다.

### 검증은 스크래치패드에서

사용자 저장소를 실험장으로 쓰지 않는다.

```
scratchpad/<이름>/ 에 tokenizer/ scanner/ go.mod testdata/ 를 복사
→ 거기서 구현·테스트·측정
→ 통과한 것만 블록으로 제시
```

**"제 쪽에서 N개 케이스로 검증하고 드립니다"** 를 지킨다. 검증 안 한 코드를 주지 않는다.

- **테스트가 실패할 수 있는지** 확인한다 — 결함을 심어 빨강이 뜨는지 본다. 측정에는 **대조군**을 둔다.
- **문서에 쓰는 주장도 검증 대상이다.** "미탐 기준은 샘플 1개뿐"을 확인 없이 썼다가 틀렸다(21개 규칙 전부 단위 테스트가 지키고 있었다).
- 측정 도구 함정: **`go run` 은 종료 코드를 `1` 로 뭉갠다**(바이너리로 잰다) · **zsh 는 `$변수` 를 공백으로 쪼개지 않는다** · 이 환경의 `grep` 은 ugrep 이라 괄호가 정규식으로 해석된다(`grep -F`).

### 한 번에 하나

"하나씩 알려주세요" 가 원칙이다. 교시 하나에 개념 하나. 관련 없는 개선을 끼워 넣지 않는다.

### 설명 방식

- Go 문법을 처음 쓰는 지점마다 짧게 설명한다 (포인터 리시버, comma-ok, `iota`, `range` 복사본 등).
- 결정에는 **왜**를 붙인다. 표로 대안과 근거를 비교한다.
- 사용자가 만든 오타/실수는 **원인을 짚되 비난하지 않는다.** "이 패턴을 보면 X를 의심하라"로 일반화한다.

---

## 2. 프로젝트 개요

HTML을 파싱해 XSS·피싱·리소스 위험을 찾는 **정적 보안 스캐너** (Go, 외부 의존성 0).

```
main.go        CLI — 파일 읽기 · 스캔 호출 · 출력만
tokenizer/     ① WHATWG 토크나이저 (브라우저와 동일하게 해석)
scanner/       규칙 계층 — scanner.go(엔진) + rules_*.go(규칙)
fetcher/       SSRF 방어 수집기 — addr.go(주소 판정) · fetch.go(DialContext·상한·리다이렉트)
web/           JSON API — POST /api/scan (my_homepage 의 nginx 뒤에서 돈다)
cmd/webscan/   API 서버 진입점 — http.Server 타임아웃 · -addr
Dockerfile     멀티 스테이지 → scratch · .dockerignore 는 허용 목록
docs/INTEGRATION.md  my_homepage 연동 명세 — API 계약 · 그리는 쪽 보안 규칙 · compose · nginx · Cloudflare · 검증 기록
tools/         measure.sh — 실전 측정 (받은 페이지는 testdata/live/, 커밋 안 함)
old_c_files/   Go 전환 전 C++ 원본 (참조용, 수정하지 않음)
testdata/      jnu_main.html(정상) · malicious_sample.html(합성 악성) · spa_shell.html
               corpus/  실제 웹에서 curl 로 받은 정상 페이지 20쪽 (+jnu_main = 회귀 기준 21쪽)
```

전신 프로젝트 두 개가 `../HtmlScanner`(C++ 13,838줄, 탐지 97종)와 `old_c_files/` 에 있다.
**둘 다 오탐/미탐의 바다가 되어 실패했다.** 그 원인 분석이 `DISCUSSION.md` 9절이다.

설계 논의 전문: [DISCUSSION.md](DISCUSSION.md) ·
Artifact: https://claude.ai/artifact/SwNhX22pnNSbMEp6X7emC3 (예전 주소 …/code/artifact/d20c0096-… 와 같은 문서, Version 21)

---

## 3. 절대 어기지 않는 설계 원칙

### Parser Differential
> 내 토크나이저가 브라우저와 다르게 해석하는 지점 = 취약점을 놓치는 지점

정규화는 토크나이저에서 끝낸다. 규칙이 대소문자·공백을 신경 쓰게 만들지 않는다.

### 점수 합산 금지
원본은 `score += w` 를 105곳에서 하고 `total >= 25 → WARN` 으로 판정했다.
**우리는 점수도 임계값도 쓰지 않는다.** 규칙은 각자 독립적으로 발견을 내고 심각도를 스스로 정한다.

### Combined 는 논리곱이지 합산이 아니다
```
❌ score += w₁; score += w₂; … if (total ≥ T)     ← 약한 신호의 합
✅ if (A && B && C)                               ← 검증 가능한 사실의 논리곱
```
각 항이 **단독으로 이진 판정·테스트 가능**해야 한다. 논리곱은 구체적 공격 패턴을 서술한다.

### HIGH 는 악성 행위에만
공격자의 흔적만 HIGH. 개발자 실수·방어 약화는 MEDIUM 이하.
그래야 HIGH가 신호로 남는다. (`weak-password-field` 가 MEDIUM인 이유)

### 세 축을 분리한다
> `Code` 는 신원(슬러그), `Class` 는 종류, `Severity` 는 정도.

H번호는 쓰지 않는다 — 두 원본이 같은 번호를 다른 뜻으로 쓴다.
Class: `exfiltration` · `execution` · `origin` · `supply-chain` · `evasion` · `hardening`

### Notes ≠ Findings
"우리가 못 본 것"은 발견이 아니다. `Result.Notes []string` — 심각도 없음, **종료 코드에 영향 없음**.
SPA 셸, WAF 차단 페이지가 여기 해당한다. 원본은 SPA에 `+12점` 을 줬다.

### 증명 가능한 것만 단정한다
`ctx.Domain == ""`(URL 미상)이면 출처 기반 규칙은 물러난다. 심각도를 낮추거나 보고하지 않는다.

### 규칙은 구조를 스택에 묻는다
토큰만 보고 "폼이다"라고 판단하면 브라우저가 **무시한** 중첩 `<form>` 까지 본다.
`ctx.OpenForm()` · `ctx.FormAccepted(tok)` 를 쓴다. 스택은 **규칙보다 먼저** 갱신되므로
"열린 폼이 있는가"가 아니라 **"열린 폼이 바로 이 토큰인가"** 를 물어야 한다.

---

## 4. 규칙 추가 절차 (반드시 이 순서)

1. **판정 기준을 한 문장으로 쓴다** — 못 쓰면 그 규칙은 버린다
2. **실제 페이지에서 몇 건 나오는지 먼저 잰다** — 정상 페이지에 흔하면 버린다
3. **음성 케이스를 먼저 쓴다** — "정상 페이지에서 안 나오는가"
4. 양성 케이스를 쓴다
5. 구현한다
6. **`go test ./scanner -run Corpus` 로 정상 21쪽 회귀를 확인한다** — 수가 늘면 오탐
7. **`scanner/inject_test.go` 의 `attacks` 표에 공격 조각을 추가한다** — 진짜 페이지 맥락에서도 발동하는지
   (집계 규칙·페이지 판정 규칙은 제외하고 이유를 주석에 남긴다)

2번으로 실제로 버린 규칙들: iframe sandbox 누락(GTM 정상 iframe), 스킴리스 URL(정상 2건),
`data:` 길이 임계값, form action 미지정, `noscript-breakout` HIGH 조합(전제가 측정에서 반증 — DISCUSSION §12.15).

---

## 5. 검증 명령

```bash
go build ./...          # _test.go 는 컴파일하지 않는다
go vet ./...            # 컴파일러가 안 잡는 것 (도달 불가 코드 등)
go test ./...           # 642개 (서브테스트 포함) · 주입 테스트 포함 약 10초
./tools/measure.sh      # 실제 웹 50곳에 대본다 (받은 페이지는 커밋하지 않는다)
./tools/measure.sh -f   #   모두 다시 받는다
go test -short ./...    # 주입 테스트 건너뜀 — 고치는 중에 자주 돌릴 때
gofmt -l .              # 출력이 있으면 실패
docker build -t sha .   # 실행 이미지 (scratch · 비루트 · https 인증서)

# 퍼징 — 큰 변경 뒤에는 길게
go test ./tokenizer -run '^$' -fuzz FuzzTokenizer -fuzztime 5m
go test ./scanner   -run '^$' -fuzz FuzzScan      -fuzztime 5m

# 회귀 — 이제 테스트가 자동으로 잡는다 (손으로 돌릴 필요 없음)
go test ./scanner -run 'Corpus|Malicious' -v

#   TestCorpusNoFalsePositive   정상 21쪽 · HIGH == 0 · 총 47건
#   TestMaliciousSampleDetected 악성 1쪽 · HIGH >= 3 · 총 5건
# 두 방향을 같이 걸어야 한다. 한쪽만이면 "아무것도 안 찾는 스캐너"가 만점을 받는다.

# 눈으로 볼 때
./suseong-html-analyzer testdata/jnu_main.html https://www.jnu.ac.kr/        # 4건
./suseong-html-analyzer testdata/malicious_sample.html https://bank.example.com/  # 5건 (HIGH 3)
./suseong-html-analyzer testdata/spa_shell.html https://app.example.com/     # 0건 + 참고 1
```

---

## 6. 반복해서 만난 함정

| 증상 | 의심할 것 |
|---|---|
| **음성 전부 통과 + 양성 전부 실패** | 규칙이 호출되지 않거나 코드 문자열이 안 맞는다 |
| 30초 지정했는데 0.3초에 끝남 | 퍼즈 대상 이름이 틀렸다 (`no fuzz tests to fuzz`) |
| 로컬은 되는데 CI만 실패 | 파일이 커밋되지 않았다 (러너는 git에서 clone) |
| 발견이 2배 | `newRules()` 에 규칙이 중복 등록됐다 |
| **같은 줄 번호에서 에러가 여러 번, 값이 1씩 커진다** | 판정이 집계 루프 **안**에 있다 |
| 정상 페이지에서 HIGH | 규칙이 틀렸다. `TestCorpusNoFalsePositive` 가 잡는다 |
| 출력에 `-test.v` 같은 플래그가 찍힘 | 코드가 전역 `flag` 를 건드린다 (`flag.PrintDefaults()` 잔존 등) |
| 테스트 중 발견 줄이 터미널에 찍히고 버퍼가 빔 | `fmt.Printf` 가 주입된 `stdout` 대신 진짜 stdout 에 쓴다 |
| 수정을 되돌려도 테스트가 전부 통과 | 수정만 넣고 테스트 케이스를 빠뜨렸다 |
| 건수 테스트는 통과인데 발견 위치가 한 토큰 뒤 | 관찰자·추적기가 규칙보다 **늦게** 호출된다 |
| 고친 줄이 반영 안 된 것 같은 테스트 결과 | 에디터에서 **저장하지 않았다** (`go test` 는 디스크를 본다) |
| 결함을 심었는데 "안 잡힘" | 측정 스크립트가 **빌드 실패**를 `--- FAIL` 로 세지 않았다 |
| `sed -n '/시작/,/^}/p'` 결과가 잘림 | `}{` 같은 줄이 범위 끝으로 오인된다. 읽지 말고 **실행해서 값을 찍어라** |
| 검증 도구가 "문제 없음"이라는데 실제로는 돌지도 않음 | `도구 | head && echo 통과` — **파이프의 종료 코드는 마지막 명령(head) 것**이라 앞의 실패가 가려진다. zsh 에는 bash 의 `PIPESTATUS` 도 없다(빈칸). 출력을 파일로 받고 `$?` 를 직접 본다. **대조군(일부러 틀린 입력)** 이 실패하는지 같이 본다 — actionlint 가 git 저장소가 아니라 시작도 못 했는데 통과로 보였다(2026-09-16) |
| **스크래치패드 명령이 사용자 저장소를 바꿈** | `cd 스크래치패드 && …` 가 실패하면 **다음 줄부터는 이전 작업 디렉터리에서** 돈다. 스크래치패드는 세션 중에 비워질 수 있다(2026-09-15 실제로 `perl -pi` 가 `main.go` 를 고침 — `git diff` 로 한 줄뿐임을 확인하고 되돌림). 검증 스크립트는 **`set -e` + 절대 경로 + `mkdir -p` 먼저** |

**도구가 못 잡은 실제 결함들** — 테스트가 유일한 방어선이었다:
`!` 누락(무한 루프) · `s = s`(자기 대입) · `" atob("` 앞 공백 하나 ·
`"iframe-snadbox-escape"` 오타 · `.gitignore` 의 `coverage.*` 가 `scanner/coverage.go` 를 삼킴 ·
`urlMixedContent` 죽은 함수

`.gitignore` 패턴에는 **`/` 를 붙인다** (`/coverage.out`, 아니면 어느 깊이에서든 잡힌다).

---

## 7. 현재 상태 · 다음 할 일

```
규칙 23종 · 테스트 642개 · 정상 코퍼스 21쪽 · 실전 측정 도구(tools/measure.sh) · 퍼징 5,600만 케이스 무결
원본 97개 항목 이식 완료 (이식 18 · 조합 재료 3 · 버림 76)
실전 43쪽 측정: 393건 → 115건 · HIGH 0건 | 커버리지 main 98.5% · scanner 99.0% · tokenizer 95.1%
패키지: tokenizer · scanner · fetcher(47~49교시, SSRF 방어 + 자원 상한) · web(51~52교시, JSON API) · cmd/webscan
```

> 26~54교시의 상세는 **DISCUSSION.md 12절**에 있다. 아래 요약은 압축 후 방향을 잃지 않기 위한 것이다.

---

### ▶ 다음 할 일 — 도구에서 서비스로 (2026-09-15 결정 · 같은 날 배포 구조 확정으로 수정)

> **배포 구조 (사용자 확인, `/Users/suseong/test/my_homepage` 를 읽어 확인):**
> ```
> 브라우저 ─443─▶ nginx ─┬─ /             정적 html/index.html (페이지는 my_homepage 가 담당)
>                        ├─ /api/…        ▶ api:8000  (FastAPI, expose 만)
>                        └─ /api/scan     ▶ sha:8080  (이 Go 프로젝트, expose 만) ← 붙일 것
> ```
> SHA 는 my_homepage 의 `tools/SHA` 로 들어가 **Docker 로 뜨고 내부 통신**한다. **Go 는 HTML 이 아니라 JSON 을 돌려준다.**
> **내 실수**: 51교시에서 Go 가 페이지 자체를 서빙한다고 가정하고 폼 페이지·`report` 패키지를 만들었다.
> 웹 계층을 짜기 전에 **배포 구조를 먼저 물었어야 했다.** → `report/` 와 폼 페이지는 사용자 위임으로 삭제(52교시 직전).
> **API 로 바뀌어도 책임은 사라지지 않고 옮겨 간다:**
> - 출력 이스케이프(50교시) → **`index.html` 의 JS**. 현재 `repoCardHtml`·`postCardHtml` 이 템플릿 리터럴을 `innerHTML` 에
>   이스케이프 없이 넣는다(`html/index.html:617-619`, `708-710`). 자기 데이터라 지금은 위험이 낮지만 **스캔 증거를
>   같은 방식으로 붙이면 suseong.org 에 XSS.** `marked.parse` → `innerHTML` 도 같은 패턴(marked 는 소독 안 함).
> - CSP·보안 헤더 → **nginx** (현재 `nginx.conf` 에 보안 헤더 0개). 남용 방지 → **nginx `limit_req`** (Go 는 nginx IP 만 본다).
> - SSRF 방어는 Go 에 그대로이고 Docker 에서 **더 중요**: compose 서비스 이름은 `172.18.0.x`(private), 내장 DNS 는
>   `127.0.0.11`(loopback) — 47교시 판정이 이미 막는다. 문자열 검사였다면 `http://api:8000/` 이 통과했다.
> - 컨테이너 안에서는 `-addr 0.0.0.0:8080` (127.0.0.1 이면 nginx 가 못 닿는다). 외부 차단은 compose 의 `expose`.
>
> **새 순서 (같은 날 다시 수정 — my_homepage 는 사용자가 나중에 직접 작업한다):**
> ~~52교시 JSON API~~ **완료**. **my_homepage(index.html · nginx · compose)는 이 수업 범위가 아니다.**
> 대신 넘겨줄 **명세**를 이 저장소에서 만든다. 명세에 **반드시** 들어갈 것:
> ① API 계약 — `POST /api/scan`, `Content-Type: application/json`, `{"url"}` → `{"url","findings":[…],"notes":[…]}` ·
>   오류는 `{"error"}` + 400/413/415/502 · 빈 결과도 `[]` · `url` 은 최종 URL · 정렬은 서버가 끝냄
> ② **그리는 쪽 보안 요구** — `evidence`·`title`·`url`·`notes` 는 **공격자가 고른 문자열**이다. `innerHTML`·템플릿 리터럴 금지,
>   `textContent`·`createElement` 로. 현재 index.html 의 `repoCardHtml`·`postCardHtml` 패턴을 그대로 쓰면 XSS.
>   `notes` 가 있으면 "발견 없음"을 "안전"으로 보여주지 말 것(SPA 셸). 대상 URL 을 클릭 가능한 링크로 만들지 말 것.
> ③ nginx — `location /api/scan` → `sha:8080` · 보안 헤더(CSP 등) · `limit_req`(Go 는 nginx IP 만 본다) · 요청 본문 상한
> ④ compose — `expose` 만(`ports` 금지) · 컨테이너 안에서 `-addr 0.0.0.0:8080`
> ⑤ **Cloudflare 프록시 뒤라면(사용자: 운영 서버는 Cloudflare 인증서) — 확인 전 조건부:**
>   - nginx 의 `$remote_addr` 는 방문자가 아니라 **Cloudflare 엣지 IP**. 지금 `X-Real-IP $remote_addr` 도 엣지 IP.
>     `limit_req` 가 엣지 단위로 걸린다 → `set_real_ip_from <Cloudflare 대역>` + `real_ip_header CF-Connecting-IP`
>     (Cloudflare 대역에서 온 연결의 헤더만 믿어야 한다 — 원서버에 직접 붙으면 누구나 헤더를 위조한다).
>   - **SHA 가 원서버 IP 를 흘린다.** 공격자가 자기 서버 URL 을 넣으면 접속 로그에 원서버 IP 가 찍힌다 →
>     Cloudflare 를 우회해 원서버를 직접 칠 수 있다. 대응: 원서버 80/443 을 **Cloudflare 대역만 허용** ·
>     또는 SHA 의 나가는 연결을 **다른 IP(프록시/VPN)** 로 — 위협 표의 "우리 IP 노출" 행이 여기서 현실이 된다.
>   - 이미지의 CA 인증서 묶음은 **나가는 쪽**(스캔 대상 검증)용이다. 사이트의 Cloudflare 인증서(들어오는 쪽, nginx)와 무관.
> **이 저장소 쪽 남은 일**: ~~Dockerfile~~(53교시) · ~~명세 문서~~ → **`docs/INTEGRATION.md`** · ~~Artifact 따라잡기~~ → Version 21 (논의 12-20 ~ 12-23).
> 명세의 설정·코드는 전부 compose 로 띄워 검증했고, 문서에서 코드 블록을 뽑아 다시 돌려 옮겨 적기 오류도 확인했다.
> **명세를 고칠 때도 같은 방식으로 다시 검증한다** (7절 검증 기록 표를 함께 갱신).
> **Go 버전 (2026-09-15 측정)**: go1.24.6 은 지원 종료 줄. `govulncheck -mode=binary` 로 **우리 코드가 호출하는 표준 라이브러리
> 취약점 26건**(net/url · net/http · crypto/tls · crypto/x509 · net — fetcher 경로). go1.27.1 은 0건, 테스트 638개 그대로 통과.
> 1.24.6 을 고른 이유는 go.mod·로컬과 맞추기였고 **지원 상태를 확인하지 않은 내 실수**. → go.mod `go 1.27.1`
> (로컬 `GOTOOLCHAIN=auto` 라 자동 전환 확인 · CI 는 `go-version-file: go.mod`) · Dockerfile `golang:1.27-alpine`(패치는 재빌드 때 따라옴).
> 공식 golang 이미지는 `GOTOOLCHAIN=local` 이라 자동 전환 안 됨.
> **나중 계획 (2026-09-16 사용자): Docker Hub 에 이미지를 올려 소스 없이 바로 쓰게 한다.** 그때 확인할 것:
> - **아키텍처** — 이 Mac 에서 빌드한 `sha:latest` 는 `linux/arm64` 뿐(확인함). amd64 서버에서는 안 돈다 →
>   `docker buildx build --platform linux/amd64,linux/arm64`. 빌드 단계에 `--platform=$BUILDPLATFORM` + `TARGETOS/TARGETARCH`
>   로 교차 컴파일하면 에뮬레이션 없이 빠르다(CGO_ENABLED=0 이라 가능) — **아직 재지 않았다.**
> - **남이 돌리는 이미지는 스스로 갱신되지 않는다** — CA 인증서·Go 패치가 빌드 시점에 굳는다. 올린 뒤에는 정기 재빌드와
>   CI `govulncheck` 가 선택이 아니게 된다. `latest` 만 올리지 말고 버전 태그도.
> - **받는 사람의 노출** — README 가 `-p 127.0.0.1:8080:8080` 을 쓰는 이유를 적어야 한다. `-p 8080:8080` 으로 열면
>   그 사람 서버가 **아무나 쓰는 페이지 가져오기 중계기**가 되고, 스캔 대상에 그 사람 IP 가 찍힌다.
> - 그때 README 의 Docker 절은 `docker build` 대신 `docker run <이름>:<태그>` 로 바뀐다.

사용자의 목표: **포트폴리오 웹 페이지에서 URL 을 입력받아 `curl` 로 가져와 스캔하고 결과를 보여준다.**

**위협 모델이 바뀐다.** 지금까지는 "내가 악성 사이트를 조사한다"였지만, 이제는
"임의의 사용자가 임의의 URL 을 우리 서버에 넣는다"다. **1순위 위험은 악성 사이트가 아니라 SSRF 다.**

```
http://169.254.169.254/...  클라우드 메타데이터 → 자격증명이 스캔 결과로 출력된다
http://127.0.0.1:6379/      내부 서비스
http://192.168.0.1/         내부망 장비
file:///etc/passwd          로컬 파일
```

| 위험 | VM | VPN | 실제로 필요한 것 |
|---|:---:|:---:|---|
| SSRF (내부망·메타데이터) | ❌ | ❌ | **주소 검증 (코드)** |
| 우리 IP 노출 | ❌ | ✅ | VPN/프록시 |
| curl·파서 취약점 → 호스트 침해 | ✅ | ❌ | VM/컨테이너 |
| 결과 페이지의 **저장형 XSS** | ❌ | ❌ | **출력 이스케이프 (코드)** |
| 리소스 고갈(거대·느린 응답) | 일부 | ❌ | 크기·시간 제한 (코드) |
| 우리 서버가 스캐닝 도구로 남용 | ❌ | ❌ | rate limit · 로그 |

**절반이 코드 문제다. 인프라로는 안 막힌다.** 그래서 순서는:

1. ~~**`fetcher` 패키지**~~ → **47·48·49교시에서 완료.**
   `fetcher/addr.go`(`blockedReason`) · `fetcher/fetch.go`(`dialChecked`·`checkRedirect`·`readLimited`·`Get`).
   주소 검증 · DNS 재바인딩 방어 · 타임아웃 10초 · 5MB · 리다이렉트 3홉 · scheme 재검사 · 쿠키 없음.
   **변이 검사 37/37 · 커버리지 90.7%.**
   `Get` 은 `*Page{URL, Body}` 를 돌려준다 — **`URL` 은 리다이렉트를 따라간 최종 주소다.**
   **스캐너의 `Context.Domain` 은 반드시 이 값을 써야 한다** (요청 URL 로 판정하면
   `mybank.com` → `evil.com` 리다이렉트에서 `evil.com` 의 로그인 폼을 같은 출처로 본다).

2. ~~**출력 이스케이프**~~ → **50교시에서 완료.** `report/html.go`(`WriteHTML`) — `html/template` + 상수 템플릿 +
   `<meta charset>`(앞 1024바이트) + `<meta>` CSP. **자기 스캔 테스트**: 악성 페이지 리포트를 우리 스캐너로 다시 검사해 0건.
   대상 URL 은 링크로 만들지 않는다(악성일 수 있는 곳으로 사용자를 보내지 않는다).
3. **웹 계층 → 51교시** — `fetcher` 와 `report` 를 `http.Handler` 로 잇는다. CSP 를 **응답 헤더**로 ·
   우리 서버가 스캐닝 도구로 남용되지 않게(rate limit · 로그).
4. **격리 운영** — VM/컨테이너/VPN. 코드가 안전해진 뒤 덧붙이는 층이다.

### 보류 항목 (성격이 다르니 섞지 말 것)

| 항목 | 성격 |
|---|---|
| **HIGH 규칙 8종** | 정상 사이트에 안 나오는 게 정상 — 검증하려면 **악성 표본**이 필요 |
| foster parenting | 트리 필요, 보안 영향 불명 |
| 단일 체계 위조(`аррӏе`) | 유니코드 confusables 표 필요 |
| eTLD+1 표 확장 | 기계적, 미탐 방향 |

### C-TAS 실측 (2026-09-15) — 규칙의 한계가 드러났다

```
/Users/suseong/test/202609_block_ip_level2_1789403460075.json       IP 1,949개 (악성코드 유포지 1,780)
/Users/suseong/test/202609_block_domain_level2_1789435860256.json   도메인 918개 (피싱 896)
```

- IP 파일은 **전부 IP** 라 HTML 표본으로 쓸 수 없다(가상호스팅이라 IP 직접 접속으로는 그 페이지가 안 나온다).
- 도메인 918개 중 punycode **63개(6%)**, 그 라벨의 문자 체계는 **전부 한글 단일**.
  `등기수령서비스.com` · `법원등기간편검색.com` · `온라인민원창구365.com` 같은 것들이다.
- **`mixed-script-host` 가 잡는 것: 0개.** 실제 한국 피싱은 호모그래프가 아니라 **의미로 속인다.**
  도메인 문자열만으로는 원리적으로 못 잡는다(의미 판단 = §9 에서 버린 키워드 목록의 길).
  → **HTML 을 봐야 잡는다**: 로그인 폼이 외부로 가면 `cross-origin-password-form` 이 잡는다.
- urlscan.io: C-TAS 도메인 **0/10** 기록 없음(한국 대상이라 국제 서비스에 안 올라옴),
  `tags:phishing` 검색은 **403**(무료 API 키 필요). 키가 있으면 **저장된 DOM** 을 받을 수 있고,
  그때는 악성 서버와 우리 사이에 통신이 없다.
- **악성 도메인에 직접 접속하지 않는다.** 차단 목록 시점이라 상당수가 죽었고, 살아있는 것에 접속하면
  우리 IP 가 공격자 로그에 남는다. 얻을 것보다 잃을 것이 크다.

---

### 지난 교시 요약

**26·27교시** — eTLD+1 · 호스트별 집계 · 정상 코퍼스 12쪽 · `corpus_test.go`.
**28교시** — `run(args, stdout, stderr)` 로 CLI 테스트 가능화 · `main_test.go` · `severity_test.go`(상수 순서 단언).
**29교시** — 코퍼스에 공격 19종 주입 측정(456건 미탐 0) · 중첩 폼 HIGH 오탐 수정(`FormAccepted`).
**30교시** — `formDestination`·`isSubmitter` 헬퍼(`rules_credential.go`). `form-action-ip`·`exfil-channel` 이
`<button formaction>`·`<input type=submit|image formaction>` 도 본다. button 은 type 이 button·reset 이 아니면 전부 submit.
**31교시** — `credentialTracker`(`scanner/submission.go`)가 폼마다 비밀번호 여부·formaction 을 모아
늦게 온 토큰에서 `ctx.CredentialDestinations()` 로 내놓는다. 비밀번호 규칙 3종은 판정만.
추적기는 **규칙보다 먼저** 호출(늦으면 발견이 다음 토큰으로 밀림 — `TestCredentialOffset`).
폼 하나·전송지 하나당 1건(비밀번호 확인 칸이 있어도 1건).
**32교시** — `inject_test.go`: 코퍼스 12쪽 × 공격 24종 × 위치 4곳(body 시작·끝 / 주석·textarea 대조군), 발견 오프셋이
주입 구간 안인지로 판정, `-short` 면 건너뜀. 결함 5종 비교에서 **textarea 무방비는 이 테스트만** 잡았고,
**escaped 없는 이중 이스케이프는 아무도 못 잡아** `TestScriptEscaped/문자열속script태그` 추가.
주입 테스트는 위치가 한 토큰 밀리는 결함은 못 잡는다(`TestCredentialOffset` 몫).
**33교시** — `<noscript>` 를 원시 텍스트로(스크립트가 켜진 브라우저 기준). 속성값에 숨긴 `</noscript>` 로 탈출한
`<img onerror>` 를 놓치던 미탐. 대가: noscript 안 공격 23종이 안 보임(8종은 원래 실행 불가, 15종은 스크립트 끈 사용자만).
`scanner/differential_test.go` 신설 — 브라우저와 해석이 갈리는 입력 모음. 주입 위치에 `noscript` 대조군 추가.
**34교시** — `Tokenizer.Truncated()`(EOF 가 구조 한가운데서 오면 참, 여섯 곳에서 표시) · `noscript-breakout`
(MEDIUM evasion, `scanner/rules_noscript.go`): noscript 내용을 다시 토큰화해 끊기면 뒤따르는 `</noscript>` 에서 보고.
오타 가능성 때문에 MEDIUM. 주입 표에서는 제외(감싸도 여전히 탈출이라 noscript 대조군 기대가 반대).

**37교시** — `form="id"` 원격 연결(명세의 form owner). `collectForms` 가 스캔 전에 id→form 맵을 만들고
`ctx.OwnerForm(tok)` 이 form 속성 우선 · 없으면 조상 폼을 돌려준다. `credentialTracker` 는 폼 오프셋 키 맵으로 일반화.
**"트리 구성"의 정체가 바뀌었다** — 보류 셋 중 둘(외래 콘텐츠 · `form=id`)은 트리가 아니라 스택·맵이었다.
진짜 트리가 필요한 건 foster parenting 뿐이고, 그건 보안 영향이 가장 불분명하다.

**38교시** — 코퍼스 12쪽 → 17쪽(위키백과 다국어 · 동아일보 이모지 · BBC · 네이버 · neverssl 평문 http).
규칙 22종 중 코퍼스에서 발동하는 것은 **5종뿐** — 나머지 17종은 "안 나오는 게 목표"와 "아직 시험 안 됨"이 섞여 있다.
**39교시** — `zero-width` 를 문자 체계 인식으로. ZWNJ 는 아랍·인도계, ZWJ 는 이모지에서 맞춤법상 필수다.
`unicode.Scripts` 표를 쓰므로 외부 의존성 0 유지. 위키백과 2→0, 동아일보 9→6, jnu_main 4 유지.

**40교시** — RFC 3492 punycode 디코더 직접 구현(`scanner/punycode.go`, 112줄). 표준 라이브러리에 없고
`x/net/idna` 는 외부 의존성이라 직접 만들었다. 파이썬 독립 구현과 벡터 8개 대조 · `FuzzPunyDecode` 1,467만 실행.
**퍼징이 찾은 것은 코드가 아니라 내가 세운 성질이었다** — "1024글자 이하"는 임의의 상수였고,
진짜 성질은 "출력 글자 수 ≤ 입력 길이"다.
원본(`HtmlScannerHelper.cpp`)은 libidn2 + **브랜드 목록 24개** 부분 문자열로 판정해 호모그래프를 전부 놓쳤다 (DISCUSSION §12.19).

**41교시** — `mixed-script-host`(HIGH origin, `scanner/rules_idn.go`). 라틴·키릴·그리스 중 둘 이상이
한 라벨에 섞이면 의심. 한글·한자는 혼동 대상이 아니라 제외. 브랜드 목록 없이 성질로만 판정한다.
한계: `аррӏе`(전부 키릴)처럼 **섞이지 않은** 위조는 못 잡는다 — 글자 대응표 필요.

**42~44교시 (실전 측정)** — 50개 사이트를 받아 43개(27MB) 전수 스캔. HIGH 0건, 0.89초.
세 가지 오탐 유형을 찾아 고쳤다: `javascript-url` 집계 누락(melon 243건) · `zero-width` 가 조판 문자를 잡음
(WORD JOINER 는 줄바꿈 방지 문자) · `obfuscated-eval` 이 같은 파일에 있을 뿐인 것을 잡음.
**393건 → 115건(−71%).** 판정 기준: 제로폭은 **단어를 쪼갤 때만**, eval 은 **인자 안에 디코더가 있을 때만**.

**45·46교시** — `tools/measure.sh` + `tools/sites.txt` 로 실전 측정을 절차로 고정(받은 페이지는 `/testdata/live/`, gitignore).
코퍼스는 문자 체계 기준으로 넷만 선별 추가(일본어·키릴·데바나가리·아랍) → 21쪽.
**코퍼스 = 회귀 방어(작고 변하지 않음), 실전 측정 = 새 오탐 발견(크고 최신).** 섞지 않는다.
측정이 의도를 정정했다 — `wikipedia_hi` 의 ZWNJ 는 데바나가리가 아니라 아랍 문자 사이에 있었다.
인도계를 지키는 것은 39교시 단위 테스트뿐이다.

**47교시** — `fetcher/addr.go`: `blockedReason(netip.Addr) string` — 나가면 안 되는 이유, 나가도 되면 `""`.
**SSRF 방어는 URL 문자열이 아니라 해석된 주소를 본다.** 문자열 층은 원리적으로 진다(`localtest.me` 는
정상 도메인인데 A레코드가 127.0.0.1 이다). 반면 `netip.ParseAddr` 은 `127.1`·`0177.0.0.1`·`2130706433` 을
전부 거부하므로, **해석기가 돌려준 값만 받으면** 표기 장난은 우리 층에 도달조차 못 한다.
표준 라이브러리를 33개 벡터로 재서 **구멍 둘**을 찾았다:
① `IsGlobalUnicast()` 는 "공인 주소"가 아니다 — `10.0.0.1`·`fc00::1`·`240.0.0.1` 에 `true`.
  이름만 보고 허용 조건으로 쓰면 **사설망이 통째로 열린다**(`255.255.255.255` 만 특별 취급).
② IPv6 로 IPv4 를 감싼 경로를 모른다 — `::127.0.0.1`(IPv4-호환)·`64:ff9b::`(NAT64)·`2002::`(6to4)·
  `2001::/32`(Teredo) 넷 다 `IsGlobalUnicast()=true` 인데 실제로는 루프백에 닿는다.
→ 표준 함수(루프백·사설·링크로컬·멀티캐스트·미지정) + `!IsGlobalUnicast()` 그물 + **놓치는 8대역 표**.
`bool` 이 아니라 이유 문자열을 돌려준다(판정에는 증거 — 이 값이 웹 페이지에 그대로 나간다).

**48교시** — `fetcher/fetch.go`: `Fetcher.dialChecked` 를 `http.Transport.DialContext` 에 꽂는다.
**TOCTOU** — 밖에서 `LookupNetIP` → 검증 → `http.Get` 하면 **`http.Get` 이 이름을 다시 푼다.**
공격자가 TTL=0 DNS 로 1차는 공인 IP, 2차는 127.0.0.1 을 주면 끝이다(**DNS 재바인딩**).
해법은 검증을 세게 하는 게 아니라 **틈을 없애는 것** — `DialContext` 안에서 풀고·검증하고·그 주소로 접속한다.
TLS 는 안전하다: `DialContext` 는 맨 TCP 만 돌려주고 인증서·SNI 는 `Transport` 가 **URL 의 도메인**으로 한다
(`DialTLSContext` 를 쓰면 이게 깨진다 — 쓰지 말 것).
답이 여럿이고 **하나라도 내부면 이름 전체를 거부**한다("괜찮은 것만 골라 쓰기"는 재시도마다 답이 달라져 같은 경주다).
이음매는 `lookup`·`dial` 두 개, `nil` 이면 진짜 네트워크 — **깜빡하면 안전한 쪽으로 떨어진다.**
"보안을 끄는 스위치"(`guard`)를 두지 않은 이유: 그러면 테스트가 증명하는 게 없어진다.
이음매가 의미 있는 자리에 있어서 *"검증한 바로 그 주소로 나갔는가"* 를 직접 단언할 수 있다(28교시 주입 패턴).

**변이 검사 26/26** (접두사 표 8 · switch 8 · `Unmap` · 표 결과 · fetch.go 8). 세 가지를 배웠다:
① **`Unmap()` 을 빼도 테스트가 통과했다** — 죽은 코드가 아니라 **진짜 우회**였다.
  `Prefix.Contains()` 는 주소 종류가 다르면 그냥 `false` 다(알아서 unmap 해주지 않는다).
  그래서 표가 담당하는 4대역은 `::ffff:` 로 감싸면 전부 뚫렸다. 표준 함수가 담당하는 대역에만
  4-in-6 벡터가 있었던 탓에 못 봤다. **테스트의 구멍과 방어의 구멍은 보통 같은 자리다.**
② **거부 테스트는 "거부됐다"만 보면 안 된다.** `blockedReason` 을 무력화하니 테스트가 진짜로
  `169.254.169.254:80` 에 SYN 을 보내고 **멈췄다.** → `mustNotDial(t)` 로 "나가지 않았다"도 단언한다.
③ **"우리가 막았다"와 "어쩌다 막혔다"는 다르다.** scheme 검사와 빈 응답 검사를 지워도 테스트가 통과했다 —
  `net/http` 가 대신 거절했기 때문이다(`unsupported protocol scheme`, `DialContext hook returned (nil, nil)`).
  표준 라이브러리 동작이 바뀌면 조용히 뚫린다. → 단언을 *"오류가 났나"* 에서 *"**우리** 메시지가 났나"* 로 바꿨다.
  같은 맥락에서 **아무것도 지키지 않는 단언 한 줄**도 찾아 지웠다(`url.Error` 가 URL 을 자동으로 덧붙이므로
  오류에 host 가 담겼는지 보는 단언은 공짜로 통과한다).

**49교시** — 자원 상한. **48교시가 "어디로 나가는가"였다면 49교시는 "나간 뒤 상대가 무엇을 통제하는가"다.**
연결이 성사된 순간부터 응답 시간·크기·홉 수를 **상대가 정한다.** 측정: 3초 지연 서버를 3.002초 그대로 기다렸고
오류도 없었다. 무한 리다이렉트는 10회에서, `file://` 리다이렉트는 `unsupported protocol scheme` 으로 멈췄지만
**막은 건 우리가 아니라 net/http 였다** — 48교시 기준에 따라 둘 다 우리 것으로 가져왔다.
`Timeout`·`MaxBytes`·`MaxHops` 는 **0 이면 기본값**(10초·5MB·3홉) — 깜빡해도 무제한이 되지 않는다.
상한은 대문자(진짜 설정), 이음매는 소문자(테스트 장치).
**핵심 함정 — 조용한 절단.** `io.ReadAll(io.LimitReader(r, max))` 는 *"정확히 max"* 와 *"넘쳐서 잘림"* 을
구별하지 못한다(둘 다 max 바이트, `io.EOF` 없음). 측정으로 확인: 41바이트 `<p>ok</p><script>fetch('//evil')</script>`
가 `"<p>ok</p><script>fet"` 로 잘리고 **오류가 없다.** 스캐너가 이걸 "깨끗함"이라 보고한다 —
**우리 방어가 우리 미탐을 만든다.** 해법은 `max+1` 을 읽어 보는 것.
`Get` 은 `*Page{URL, Body}` 를 돌려주고 `URL` 은 `resp.Request.URL`(최종 주소)다. `Jar` 를 주지 않아 쿠키는 없다.
**변이 검사에서 배운 것: 기본값과 같은 값으로 시험하면 아무것도 증명 못 한다.**
`f.MaxHops = 3` 으로 썼는데 기본값도 3 이라, 설정 읽는 코드를 통째로 죽여도 테스트가 통과했다. → `2` 로 바꿨다.
**사용자 오타에서 배운 것: 같은 리터럴을 세 번 적게 만들면 세 번 틀릴 수 있다.**
`203.0.113.7` 을 `203.0.133.7` 로 치는 실수가 **두 교시 연속 같은 자리에서** 났다. 손이 아니라 구조 문제라
`const first, second = …` 로 한 번만 적게 바꿨다. 실패 메시지도 **두 값을 나란히** 보여줘야 한다
(맞는 값만 찍히면 눈이 미끄러진다).

**50교시** — `report/html.go`. **이스케이프는 값의 성질이 아니라 자리의 성질이다.**
같은 `<img src=x onerror=alert(1)>` 를 여섯 자리에 넣어 쟀다 — HTML 본문 `&lt;`, 따옴표 없는 속성은 **공백·`=` 까지**
(`&#32;` `&#61;`), href 는 퍼센트 인코딩, script 는 `<`, style 은 `\3c`. **전부 다르다.**
`ReplaceAll("<","&lt;")` 류로는 원리적으로 안 된다 — 자리를 모르면 올바른 이스케이프를 고를 수 없다.
`html/template` 은 템플릿을 파싱해 각 `{{.}}` 의 문맥을 알아낸다. href 의 `javascript:`·`&#106;avascript:`·`data:` 는 `#ZgotmplZ`.
**재 보니 지켜주는 것**: svg 안 · 주석 안(주석을 통째로 삭제) · 태그 이름 자리 · 속성 이름 자리(`ZgotmplZ`).
**못 지켜주는 것은 둘뿐이고 둘 다 자초해야 일어난다**: `template.HTML(v)` 로 감싸기 · **템플릿 문자열을 사용자 입력으로 만들기**
(이스케이프의 실패가 아니라 공격자에게 템플릿을 쓰게 한 것). 그래서 `tplText` 는 상수다.
**자기 스캔 테스트** — 악성 페이지 → 스캔 → 리포트 → **리포트를 다시 스캔** → 0건. 안전 기준을 새로 만들지 않고 규칙 23종을 재사용한다.
`text/template` 변이와 `template.HTML` 변이를 둘 다 잡았다(`inline-handler "<img onerror=…>"`).
**변이 검사에서 배운 것: 살아남은 변이가 곧 빠진 테스트는 아니다.** 6개 중 3개가 살아남았는데,
진짜 구멍은 charset 하나였다(→ `TestReportDeclaresCharsetEarly`, 위치까지 단언 — 브라우저는 앞 1024바이트만 본다).
나머지 둘(증거·URL 을 `<code>` 밖으로)은 **이스케이프 결과가 똑같다** — 둘 다 HTML 본문 문맥이라 순전한 표현 선택이다.
여기에 테스트를 붙이면 마크업을 고정시키는 족쇄가 된다. **변이 검사는 후보를 내놓을 뿐, "이게 깨지면 무엇이 위험해지는가"는 내가 판단한다.**
CSP 는 2차 방어선이고 **브라우저 동작은 여기서 검증할 수 없다** — 테스트는 그 줄이 있는지만 본다.

**51교시** — `web/handler.go` · `cmd/webscan`. **신뢰 경계** — 들어오는 것은 좁히고(`MaxBytesReader` 파싱 전 ·
URL 2048자 · `r.Context()` 전달), 나가는 것은 해석을 못박는다(CSP·nosniff 를 **모든 응답**에 — 미들웨어).
**오류 상세를 내보내지 않는다** — `intranet(10.1.2.3) 로는 접속하지 않는다` 는 내부 DNS 조회 창구가 된다.
`http.Server` 에 타임아웃(`ReadHeaderTimeout` — slowloris), `WriteTimeout` 은 가져오기 상한(10초)보다 길게.
**동등 변이**를 처음 만났다: 결과 `Content-Type` 설정을 지워도 `net/http` 가 본문을 보고 **같은 값**을 채운다 — 테스트로 구별 불가.
코드에는 남긴다(우리가 정할 값이다), 테스트는 요구하지 않는다.
**52교시(구조 변경)** — 배포 구조가 확정돼(my_homepage nginx 뒤) **HTML 서빙 → JSON API** (`POST /api/scan`).
`report/`·폼 페이지는 사용자 위임으로 삭제. 정렬을 CLI 에서 `scanner.SortBySeverity` 로 내렸다(보여주는 곳이 둘).
**증거는 JSON 에 원본 그대로** — 이스케이프는 그리는 자리의 일이다. 여기서 `&lt;` 로 바꾸면 받는 쪽 `textContent` 가 글자로
`&lt;` 를 보여준다. 대신 `encoding/json` 이 `<` 를 `<` 로 써서 응답 바이트엔 날것의 `<` 가 없다.
**JSON Content-Type 만 받는다** — 폼 형식은 다른 사이트의 `<form>` 이 방문자 브라우저로 보낼 수 있다(교차 출처 JSON 은 preflight).
빈 결과도 `[]`(nil 슬라이스는 `null` — 받는 JS 가 `.length` 에서 터진다).
**정렬 테스트가 아무것도 지키지 못했다**: 표본의 LOW 가 집계 규칙(`inline-handler`)이라 **`Finish` 에서** 나오므로 정렬 전부터
HIGH 가 첫 줄이었다. 정렬 전 순서가 MEDIUM→HIGH 인 표본(`eval(atob)` 먼저)으로 바꿨다.
`sort.Slice` 는 **원소 12개 이하면 안정적으로 동작**(13개부터 흔들림) — `SliceStable→Slice` 변이는 살려 둔다(같은 심각도 안 순서일 뿐).
**사용자 오타 둘이 서로를 가렸다**: 테스트 경로 `/ap/scan`(→ 404) 뒤에 코드의 `"appictaion/json"`(→ 전부 415)이 숨어 있었다.
그리고 **`TestScanRequiresJSONContentType` 은 통과했다** — 전부 거절하는 코드는 "나쁜 것을 거절하는가"만 묻는 테스트를 통과한다.
반대 방향(좋은 요청이 200)을 묻는 테스트가 잡았다. §5 "두 방향을 같이 건다"의 API 판.
**코드와 테스트가 맞춰야 하는 약속(헤더 이름·미디어 타입)은 각자 따로 적는다** — 상수로 묶으면 둘이 같이 틀려도 통과한다
(49교시 "리터럴은 한 번만"은 **테스트 안에서만** 쓰는 설정값 얘기다).
변이 검사 17/17 · web 커버리지 97.4%.

**53교시** — `Dockerfile` · `.dockerignore`. **실행 이미지에는 필요한 것만 — 무엇이 필요한지는 재야 안다.**
세 판을 실제 컨테이너로 쟀다: `scratch` 바이너리만 8.72MB(**https 만 502**, http 200) · +인증서 한 줄 9.07MB(채택) · distroless 14.9MB.
실패 원인 `x509: certificate signed by unknown authority` — **48교시 이후 테스트는 전부 가짜 dial 이라 못 본다.**
51교시의 오류 상세 숨김 때문에 응답으로는 원인을 알 수 없었다 → 운영에는 서버 로그가 필요하다.
`USER 65532:65532`(scratch 에 /etc/passwd 없음 — 숫자로). 컨테이너 안 `127.0.0.1` 바인드는 **로그는 멀쩡한데 아무도 못 닿는다**(curl exit 52).
**Docker 네트워크 SSRF 대조군**: `api` 이름의 nginx 를 같은 네트워크에 두고 **방어 켬 502 / 끔 200**(내부 페이지를 가져옴) — 우리 방어가 막았다는 증거.
`host.docker.internal`(→192.168.65.254, 이 Mac)·`172.17.0.1` 은 **끔에서도 502**(듣는 서버 없음) — 대조군이 구별 못 함, 표로만 막힌다.
`.dockerignore` 없이 컨텍스트 40.8MB(.git·testdata/live·macOS 바이너리) → 허용 목록 300KB. **Docker 는 .gitignore 를 안 읽는다.**
`CGO_ENABLED=0` 은 golang:alpine 에서 **이미 기본값 0**(C 컴파일러 없음) — 결과를 안 바꾼다고 정직하게 주석. `-trimpath -s -w` 14.2→9.07MB.
**Go 버전 — 내 실수**: go.mod·로컬에 맞춰 1.24.6 고정. 지원 종료 줄이었고 `govulncheck -mode=binary` 로 **도달 가능한 표준 라이브러리
취약점 26건**(net/url · net/http · crypto/tls · crypto/x509 · net — fetcher 경로). go1.27.1 은 0건, 테스트 638개 그대로 통과.
CI 도 `go-version-file: go.mod` 이라 1.24.6 으로 돌고 있었다. → go.mod `go 1.27.1`(로컬 `GOTOOLCHAIN=auto` 자동 전환 확인,
공식 golang 이미지는 `local` 이라 안 됨) · Dockerfile `golang:1.27-alpine`(**줄로 적어 재빌드 때 패치를 따라간다** — 정확한 고정이 26건을 쌓았다).
**측정하다 한 실수**: "조회만"이라며 `docker run --pull=missing` 으로 이미지 4개를 받았다 — 쓸 것만 남기고 지움.

**54교시** — 요청 로그(`log/slog` JSON → 표준 출력). **로그는 운영자의 증거이자 새 유출 경로다.**
51교시에 오류 상세를 응답에서 숨긴 대가로 502 원인을 볼 곳이 없었다. 재 보니 **`err.Error()` 에 사용자가 넣은 URL 이 통째로** 들어 있었다
(비밀번호는 `***` 로 가려지지만 `?token=SECRET` 은 그대로). → 오류 문자열 대신 **종류**를 남긴다: `fetcher.ErrBlocked`·`ErrTooLarge`
(`%w` — `http.Client` 를 거쳐도 `errors.Is` 로 찾아짐 확인) + `*net.DNSError` · `*tls.CertificateVerificationError` · `net.Error.Timeout()`.
남기는 것: 상태·원인·scheme·host(포트 포함)·final_host·건수·바이트·ms. 남기지 않는 것: 경로·쿼리·조각·userinfo·본문·오류 문자열·방문자 IP.
**로그 줄 위조**: `log.Printf` 로 줄바꿈 든 값을 쓰면 2줄(가짜 줄), slog JSON 은 1줄. `url.Parse` 는 호스트의 줄바꿈은 거부하지만
**경로의 `%0A` 는 진짜 줄바꿈으로 풀어 준다** — 경로를 안 남기는 이유가 하나 더. `newHandler` 는 로그를 버리는 판으로 남겨 기존 테스트 11개 무수정.
**JSON 핸들러 선택은 `cmd` 에 있어 테스트가 못 지킨다**(주석으로만). 변이 검사 13건 전부 잡음(처음 둘은 빌드 실패로 무효 → 다시 만듦).
**사용자 코드에서 로그 필드 줄(`findings`·`notes`·`bytes`)이 빠졌는데 테스트가 통과했다** — 내 테스트가 네 필드만 봤다.
명세 6절에 필드를 약속하므로 단언을 넣었다(`log_test.go` 는 사용자 위임으로 내가 고침). 명세 6절의 "로그를 남기지 않는다"를 실제 이미지 `docker logs` 로 재검증해 고쳤다.
**사고**: 사용자 `handler.go` 가 에디터 되돌리기로 옛 오타(`appictaion`)까지 되살아나 깨졌다 — 차이가 전부 손상뿐이라 백업 후 `git checkout` 으로 복구(위임).

1. **다음 방향 미정** — 남은 보류: foster parenting(트리) · eTLD+1 표 확장 · 단일 체계 위조 ·
   HIGH 규칙들은 실측 기회가 없다(정상 사이트에 안 나오는 게 정상).

> **외래 콘텐츠(`<svg>`·`<math>`)는 보류로 결정했다** (35교시, DISCUSSION §12.14).
> 미탐 방향이지만 ① 트리 구성(네임스페이스·integration point)이 필요하고 ② 반쪽 구현은 반대 방향 오탐을 만들며
> ③ 브라우저로 검증할 수단이 없다. 트리 구성을 하게 되면 그때 함께 푼다. **다시 논의하지 말 것.**
2. `<input form="id">`·`<button form="id">` 원격 연결 — 스택으로는 불가, 트리 + id 인덱스 필요
3. 전체 트리 구성 — foster parenting, 삽입 모드 23개
4. punycode 호스트 — 정상 IDN과 구별하려면 혼합 스크립트 판정 필요
5. eTLD+1 접미사 표 확장 — 24개만 내장. 표에 없으면 마지막 두 라벨로 떨어져 **미탐 방향**

### 문서 갱신 규칙

규칙을 추가하면 **README(규칙 표) · DISCUSSION.md · Artifact 셋 다** 갱신한다.
문서가 뒤처지면 사용자가 지적하기 전에 먼저 알린다.
**틀린 숫자를 기록에 남기지 않는다** — 정정할 때는 정정 사실도 함께 남긴다
(예: DISCUSSION.md 9절의 "탐지 항목 9개 → 97개" 정정).
