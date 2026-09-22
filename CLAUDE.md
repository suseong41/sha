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
- **테스트 코드는 내가 쓴다** (2026-09-19 사용자 결정 — 테스트까지 전부 치면 너무 느리다).
  스크래치패드에서 변이로 **실패할 수 있음**을 확인한 뒤 저장소에 넣고, 저장소에서 빨강까지 보여 준다.
  **구현 코드는 여전히 사용자가 친다.**
  주석은 사용자 스타일로 — 짧은 한 줄, `~함`·`~남김`·`~확인`·`~봄` 끝맺음, `->` 화살표,
  줄 끝 주석(`continue // 음성`), 표 안 `// 음성`·`// 양성`, 헬퍼는 `// 이름(): 설명.`

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
- 측정 도구 함정: **`go run` 은 종료 코드를 `1` 로 뭉갠다**(바이너리로 잰다) · **zsh 는 `$변수` 를 공백으로 쪼개지 않는다**(쪼개려면 `${=변수}` — 62교시에 또 걸림) · 이 환경의 `grep` 은 ugrep 이라 괄호가 정규식으로 해석된다(`grep -F`).

### 한 번에 하나

"하나씩 알려주세요" 가 원칙이다. 교시 하나에 개념 하나. 관련 없는 개선을 끼워 넣지 않는다.

### 설명 방식

- Go 문법을 처음 쓰는 지점마다 짧게 설명한다 (포인터 리시버, comma-ok, `iota`, `range` 복사본 등).
- 결정에는 **왜**를 붙인다. 표로 대안과 근거를 비교한다.
- 사용자가 만든 오타/실수는 **원인을 짚되 비난하지 않는다.** "이 패턴을 보면 X를 의심하라"로 일반화한다.

---

## 2. 프로젝트 개요

HTML을 파싱해 XSS·피싱·리소스 위험을 찾는 **정적 보안 스캐너** (Go, 외부 의존성 0).
이름은 **SHA**(Suseong-Html-Analyzer). 식별자는 전부 소문자 `sha` — 모듈 `github.com/suseong41/sha` · 저장소 `suseong41/sha` · 이미지 `suseong41/sha` · 실행 파일 `sha`.
**2026-09-21 에 옛 이름(`suseong-html-analyzer`)에서 바꿨다**(67교시). 옛 Docker Hub 저장소는 같은 날 **지웠다** — 공개 13시간 · 어디에도 알린 적 없음 · star 0 · pull 85 가 전부 자동 크롤러로 보였다(새 저장소가 1.5시간 만에 69). **받아 쓰는 사람이 있었다면 남겼을 것이다.**

```
main.go        CLI — 파일 읽기 · 스캔 호출 · 출력만
tokenizer/     ① WHATWG 토크나이저 (브라우저와 동일하게 해석)
scanner/       규칙 계층 — scanner.go(엔진) + rules_*.go(규칙)
fetcher/       SSRF 방어 수집기 — addr.go(주소 판정) · fetch.go(DialContext·상한·리다이렉트)
web/           JSON API — POST /api/scan(url 을 가져오거나 html 을 받는다 · 동시 4개 상한) · GET /healthz (my_homepage 의 nginx 뒤에서 돈다)
cmd/webscan/   API 서버 진입점 — http.Server 타임아웃 · -addr
version/       V 하나 — CLI(-version) · 서버 시작 로그 · 이미지 라벨이 같은 값을 말한다 (63교시)
Dockerfile     멀티 스테이지 → scratch · TARGETARCH 로 크로스 컴파일 · .dockerignore 는 허용 목록(첫 줄 *)
LICENSE        MIT(suseong41). 68교시에 gTest(BSD-3) 63개를 지워 제3자 코드가 없어졌고 NOTICE 도 없앴다
.github/workflows/  ci.yml(gofmt·vet·test·빌드·스모크·govulncheck·퍼징·**이미지 빌드**) · release.yml(v* 태그 → Docker Hub)
docs/INTEGRATION.md  my_homepage 연동 명세 — API 계약 · 그리는 쪽 보안 규칙 · compose · nginx · Cloudflare · 검증 기록
tools/         measure.sh — 실전 측정 (받은 페이지는 testdata/live/, 커밋 안 함)
old_c_files/   Go 전환 전 C++ 원본 (참조용, 수정하지 않음). gTest 를 지워 **지금은 빌드되지 않는다** — 읽기용이다
testdata/      jnu_main.html(정상) · malicious_sample.html(합성 악성) · spa_shell.html
               corpus/  실제 웹에서 curl 로 받은 정상 페이지 20쪽 (+jnu_main = 회귀 기준 21쪽)
```

전신 프로젝트 두 개가 `../HtmlScanner`(C++ 13,838줄, 탐지 97종)와 `old_c_files/` 에 있다.
**둘 다 오탐/미탐의 바다가 되어 실패했다.** 그 원인 분석이 `DISCUSSION.md` 9절이다.
그보다 앞선 **첫 연구**는 `/Users/suseong/test/message.txt`(파이썬 정적 스캐너, 정규식 추출 + 점수 합산) — 검토는 DISCUSSION §9.8.
설정 파일을 `exec` 하므로 **실행하지 말고** 함수만 import 해서 잰다.

설계 논의 전문: [DISCUSSION.md](DISCUSSION.md) ·
Artifact: https://claude.ai/artifact/SwNhX22pnNSbMEp6X7emC3 (예전 주소 …/code/artifact/d20c0096-… 와 같은 문서, Version 32 — 논의 9-0(첫 연구) · 12-36~38(ransomware · 가려진 리다이렉트 · HIGH 규칙의 근거) · **12-39~44(배포 · 이름 통일 · my_homepage 연동 · Go 이관 · 스트리밍 · sri-missing 등급)** · 71교시까지. 제목도 'SHA 설계 기록'으로.
갱신은 `Artifact read` 로 받은 최신판에서 시작한다 — 스크래치패드 사본은 사라지거나 낡을 수 있다)

---

## 3. 절대 어기지 않는 설계 원칙

### Parser Differential
> 내 토크나이저가 브라우저와 다르게 해석하는 지점 = 취약점을 놓치는 지점

정규화는 토크나이저에서 끝낸다. 규칙이 대소문자·공백을 신경 쓰게 만들지 않는다.

### 점수 합산 금지
원본은 `score += w` 를 105곳에서 하고 `total >= 25 → WARN` 으로 판정했다.
**우리는 점수도 임계값도 쓰지 않는다.** 규칙은 각자 독립적으로 발견을 내고 심각도를 스스로 정한다.

### 경계가 필요하면 분포의 틈에서만
비율 경계("90% 미만")를 세우고 싶으면 **음성과 양성의 분포를 나란히 그린다.** 두 분포 사이에 틈이 있으면 그 틈이 근거고,
틈이 없으면 경계가 아니라 **있다·없다**로 가른다. 62교시: 셸코드는 "문자로 풀리는 비율"이 80~95%에 몰려 90% 가 그 한가운데였고,
escape 한 실제 글은 **전부 정확히 100%** 였다 → "글이 아닌 값이 하나라도 있는가"로 바꿔 임계값이 사라졌다.

### 숫자에는 출처를 적는다
코드에 남는 숫자는 **측정값**이거나 **제품 판단**이다. 둘을 구분해 적지 않으면 나중에 **둘 다 근거 없는 숫자로 읽힌다.**
65교시: `DefaultMaxScans = 4` 는 측정(5MB 페이지 동시 10이면 256MB 컨테이너가 죽는다 → 그 절반 이하) · `maxWait = 2초` 는 제품 판단("사람이 기다릴 만한 시간").
측정에서 나온 숫자는 **테스트로 못 박는다** — 바꾸려면 다시 재라는 뜻이다(`TestDefaultMaxScansIsMeasured`).

### Combined 는 논리곱이지 합산이 아니다
```
❌ score += w₁; score += w₂; … if (total ≥ T)     ← 약한 신호의 합
✅ if (A && B && C)                               ← 검증 가능한 사실의 논리곱
```
각 항이 **단독으로 이진 판정·테스트 가능**해야 한다. 논리곱은 구체적 공격 패턴을 서술한다.

### 심각도는 네 칸이고, 경계를 적어 둔다
**HIGH** — 공격자의 흔적. 정상 사이트에 있을 이유가 없다.
**MEDIUM** — 이 페이지에 **실재하는 약점**이고 **운영자가 고칠 수 있다**(`javascript-url` · `iframe-sandbox-escape` · `weak-password-field`).
**LOW** — **위험의 재료**이거나 다른 설명이 가능한 것, 또는 굳힘(hardening)을 가로막는 요소(`inline-handler` · `zero-width` · `sri-missing`).
**INFO** — 전제를 확인하지 못했거나(`mixed-content` 는 페이지가 https 로 확인될 때만 MEDIUM) 요즘 브라우저에서 해소된 것(`target-blank-no-rel`).
71교시까지 **이 경계가 글로 없었다** — "HIGH 는 악성 행위에만"만 있었다. 그래서 `sri-missing` 의 등급을 물었을 때 근거를 댈 수 없었다.
등급은 **출력 계약**이다(종료 코드 · API 의 `severity`). `TestEveryRuleSeverity` 가 25종 전부를 못으로 박는다 — 바꾸려면 재서 근거를 남기고 그 표를 함께 고친다.

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

**구조 판정은 한 곳에서 하고, 규칙은 그 결과를 묻는다.** 스크립트가 코드 블록인가는 `<script>` 시작 태그에서
`ctx.scriptCode` 가 정하고(`codeScript()`), 스크립트 규칙은 **`scriptText()` 로만** 읽는다. 규칙마다 따로 판정하면
빠뜨린 규칙이 구멍이 된다 — 61교시에 `exfil-channel` 이 GitHub 코드 화면(JSON 데이터 블록)에서 HIGH 를 냈다.

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
go test ./...           # 645개 (서브테스트 포함) · 주입 테스트 포함 약 10초
./tools/measure.sh      # 실제 웹 50곳에 대본다 (받은 페이지는 커밋하지 않는다)
./tools/measure.sh -f   #   모두 다시 받는다
go test -short ./...    # 주입 테스트 건너뜀 — 고치는 중에 자주 돌릴 때
gofmt -l .              # 출력이 있으면 실패
docker build -t sha .   # 실행 이미지 (scratch · 비루트 · https 인증서)
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...   # 알려진 취약점 — CI vuln 잡이 푸시·주간에 돌린다

# 퍼징 — 큰 변경 뒤에는 길게
go test ./tokenizer -run '^$' -fuzz FuzzTokenizer -fuzztime 5m
go test ./scanner   -run '^$' -fuzz FuzzScan      -fuzztime 5m

# 회귀 — 이제 테스트가 자동으로 잡는다 (손으로 돌릴 필요 없음)
go test ./scanner -run 'Corpus|Malicious' -v

#   TestCorpusNoFalsePositive   정상 21쪽 · HIGH == 0 · 총 47건
#   TestMaliciousSampleDetected 악성 1쪽 · HIGH >= 3 · 총 5건
# 두 방향을 같이 걸어야 한다. 한쪽만이면 "아무것도 안 찾는 스캐너"가 만점을 받는다.

# 눈으로 볼 때
./sha testdata/jnu_main.html https://www.jnu.ac.kr/        # 4건
./sha testdata/malicious_sample.html https://bank.example.com/  # 5건 (HIGH 3)
./sha testdata/spa_shell.html https://app.example.com/     # 0건 + 참고 1
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
| **도구를 고쳤는데 새 조건 줄이 출력에 없다** | 빌드가 실패해 **옛 바이너리가 돌았다** — `a && b && c` 는 중간에 멈춰도 **다음 줄**은 돈다. 빌드 전에 바이너리를 `rm` 하고, vet·build 실패면 `exit 1` (62교시) |
| **진단 테스트가 아무것도 안 찍는다** | `go test ./패키지` 는 **통과한 테스트의 표준 출력을 숨긴다** — `-v` 를 붙인다. 62교시에 이걸 모르고 "글에는 비문자가 없다"고 결론냈다가 철회했다(실제로는 서식 문자가 있었다) |
| `sed -n '/시작/,/^}/p'` 결과가 잘림 | `}{` 같은 줄이 범위 끝으로 오인된다. 읽지 말고 **실행해서 값을 찍어라** |
| 검증 도구가 "문제 없음"이라는데 실제로는 돌지도 않음 | `도구 | head && echo 통과` — **파이프의 종료 코드는 마지막 명령(head) 것**이라 앞의 실패가 가려진다. zsh 에는 bash 의 `PIPESTATUS` 도 없다(빈칸). 출력을 파일로 받고 `$?` 를 직접 본다. **대조군(일부러 틀린 입력)** 이 실패하는지 같이 본다 — actionlint 가 git 저장소가 아니라 시작도 못 했는데 통과로 보였다(2026-09-16) |
| **이름을 일괄 치환한 뒤 문서가 거짓말을 한다** | 치환은 **과거를 말하는 문장**도 바꾼다. 67교시: "옛 이미지 `…suseong-html-analyzer:0.1.0`" 이 새 이름으로 바뀌어 **없는 것을 가리키는 문장**이 됐다. 치환 뒤에는 `git diff` 에서 **이력·이전 안내**를 따로 훑는다 |
| **거르는 설정을 넣었는데 그대로 들어간다** | **허용 목록은 맨 앞에 `*` 가 있어야 한다.** `!` 는 "앞서 제외한 것을 되살린다"라서 제외 줄이 없으면 아무것도 안 걸러진다. 2026-09-20 배포 준비 점검에서 발견 — 커밋된 `.dockerignore` 에 `*` 가 없어 `testdata/live` 의 받은 페이지가 빌드 컨텍스트로 갔다(§12.30 정정). **잰 파일과 커밋된 파일이 다를 수 있다**: 거르는 설정은 크기가 아니라 **무엇이 들어갔는지 목록**으로 확인한다(`COPY . /ctx` 뒤 `find`) |
| **스크래치패드 명령이 사용자 저장소를 바꿈** | `cd 스크래치패드 && …` 가 실패하면 **다음 줄부터는 이전 작업 디렉터리에서** 돈다. 스크래치패드는 세션 중에 비워질 수 있다(2026-09-15 실제로 `perl -pi` 가 `main.go` 를 고침 — `git diff` 로 한 줄뿐임을 확인하고 되돌림). 검증 스크립트는 **`set -e` + 절대 경로 + `mkdir -p` 먼저** |
| **로컬은 위반 0인데 운영에서만 위반이 난다** | **앞단(CDN)이 지나가는 HTML 을 고친다.** 72교시: Cloudflare 가 분석 비컨을 `</body>` 앞에 끼워 넣는데 **`Accept: text/html` 인 요청에만** 넣어, 맨 `curl` 로 받은 본문에는 **없었다**. 운영 확인은 **브라우저처럼 보이는 요청**(`-A` + `Accept`)으로 하고, 페이지에 무엇이 실렸는지는 우리 파일이 아니라 **방문자가 받는 바이트**로 센다 |
| **`grep -c` 결과가 눈에 보이는 수와 다르다** | `-c` 는 **일치한 줄 수**다. 헤드리스 Chrome 의 `--dump-dom` 은 한 줄이라 카드 4개가 `1` 로 나온다 — 개수는 `grep -o … \| wc -l` |

**도구가 못 잡은 실제 결함들** — 테스트가 유일한 방어선이었다:
`!` 누락(무한 루프) · `s = s`(자기 대입) · `" atob("` 앞 공백 하나 ·
`"iframe-snadbox-escape"` 오타 · `.gitignore` 의 `coverage.*` 가 `scanner/coverage.go` 를 삼킴 ·
`urlMixedContent` 죽은 함수

`.gitignore` 패턴에는 **`/` 를 붙인다** (`/coverage.out`, 아니면 어느 깊이에서든 잡힌다).
`.dockerignore` 는 **허용 목록**이다 — 첫 줄이 `*`, 그 뒤가 `!` 목록. `*` 가 빠지면 조용히 전부 통과한다.

| 증상 | 원인 |
|---|---|
| **양성 전부 0건 + 정상 코퍼스에 엉뚱한 HIGH** | 규칙이 **다른 것을 찾고 있다.** 59교시: `range localHotst` — 자동완성이 같은 타입(`[]string`)의 기존 변수를 골라 컴파일됐고, 새 목록 `localObjects` 는 안 쓰여도 **패키지 수준 변수라 오류가 없다**(Go 는 안 쓴 import·지역 변수에만 오류). `go vet` 도 말이 없다. 코퍼스 회귀가 없었다면 "안 뜬다"까지만 보였다 |
| **같은 규칙인데 한 표기만 실패한다** | **문자열 안의 오타**를 의심한다. 컴파일러·`go vet`·gofmt 는 문자열의 뜻을 보지 않는다. 60교시 `"sfade-mode"`: 하이픈 경우만 실패하고 밑줄 경우(`밑줄표기`)는 통과해 위치가 드러났다 — 그래서 **표기마다 경우를 따로** 둔다 |
| **변이가 "살아남음"인데 이상하다** | 변이가 **적용되지 않았을** 수 있다. 치환할 줄이 파일에 두 번 이상 있으면 스크립트가 거부하는데, 그 실패를 확인하지 않으면 **원본 코드로 테스트가 돈다**(59교시에 2건). 변이 스크립트는 적용 실패 시 멈추게 하고, 치환 문자열에는 그 규칙에만 있는 앞뒤 줄을 넣는다 |

---

## 7. 현재 상태 · 다음 할 일

```
규칙 25종(HIGH 11) · 테스트 769개 · 정상 코퍼스 21쪽 · 실전 측정 도구(tools/measure.sh) · 퍼징 5,600만 케이스 무결
C-TAS 악성 HTML 24,636개: HIGH 표본 3,955 · 공격 분류 발견 0건 13,240(54%) — 62교시 기준, 측정 도구는 보류 표 참고
  └ HIGH 11종 중 실제 표본으로 확인된 것은 5종(local-system-object 3,741 · encoded-shellcode 154 · webshell-signature 59 ·
    form-action-ip 9 · data-uri-document 3). 나머지 6종은 합성·주입뿐 — URL 없음 2 · 비ASCII 없음 1 · 피싱 표본 없음 3(§12.46)
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
| **HIGH 규칙 11종** (2026-09-16 셈은 10종 — 예전 표기 8종은 틀렸다. 57교시에 `cleartext-credentials` 를 MEDIUM 으로 내리고, 59교시 `local-system-object` · 62교시 `encoded-shellcode` 를 더함) | 정상 사이트에 안 나오는 게 정상 — 검증하려면 **악성 표본**이 필요. base-href-external · cross-origin-password-form · data-uri-document · encoded-shellcode · exfil-channel · form-action-ip · local-system-object · meta-refresh-scheme · mixed-script-host · phishing-interstitial · webshell-signature |
| ↳ **표본 조달 (2026-09-17)** | 사용자가 **C-TAS 에 머신러닝용 악성 HTML 데이터셋을 신청해 두었다.** 도착하면 1번을 진행한다. 받은 HTML 은 스캔만 하고 브라우저·미리보기로 열지 않으며 커밋하지 않는다(`testdata/live/` 처럼 git 에서 뺀 곳). |
| ↳ **데이터셋 도착 (2026-09-19)** | `/Users/suseong/test/dataset/` — zip 8개 4.7GB(**풀지 않는다** — 압축 파일에서 메모리로 읽어 스캔). 분류: backdoor 132 · downloader 1,043 · exploit.kit 1,600 · miner 10,000 · ransomware 323 · trojan 10,000 · virus 841 · worm 697 표본. **원본 HTML 이 아니라 머신러닝 특징값**: 표본마다 `<sha256>.json` + 바이트 그림 `.bmp` 2개. JSON 의 `strings` 가 **줄 단위로 자른 원본 문자열**(글자 합이 원본의 95~98%) → `strings.Join(s, "\n")` 으로 되살린다. **한계**: 비ASCII 가 전부 빠짐(제로폭·유니코드 도메인 규칙은 이 데이터로 못 잰다) · 빈 줄 빠짐 · **페이지 URL 모름**(출처 규칙은 설계대로 물러남, 가짜 URL 은 부풀리므로 안 씀). 출처는 VirusShare·clean-mx, `av_detection` 에 백신 진단명. 측정 도구는 스크래치패드 `ctas/tool` (저장소 밖) |
| ↳ **첫 측정 (2026-09-19, 24,636표본 · 50초)** | 발견 있음 89.8% 이지만 대부분 hardening·supply-chain(mixed-content·sri-missing·inline-handler). **HIGH 24.8% 는 착시**: `cleartext-credentials` 6,109건 중 miner 의 5,684건이 **한 사이트**(saltworld.net 포럼, 채굴 스크립트가 심긴 페이지를 페이지마다 수집 — **중복 제거 없이 비율을 내면 안 된다**). 게다가 이 HIGH 는 악성코드가 아니라 **피해 사이트의 http 로그인 폼** → §3 "HIGH 는 악성 행위에만" 과 충돌(결정 필요). **`webshell-signature` 0/132**: backdoor 표본에 시그니처가 문서 어디든 75회(c99shell 40 · r57shell 31 · byroenet 4) 있지만 `<script>` 안에는 **0회** — 규칙이 구조적으로 못 보는 자리를 보고 있었다(웹셸은 서버가 그린 관리 화면). 진짜로 보이는 HIGH: `form-action-ip` 9(`http://69.31.86.221/se.php`) · `data-uri-document` 4. 한 번도 안 뜬 HIGH: 출처 규칙(URL 없음, 설계대로) · mixed-script-host(비ASCII 빠짐) · exfil-channel·meta-refresh-scheme·phishing-interstitial(피싱이 아니라 악성코드 데이터). **재현율 구멍**: 발견 0건 비율 exploit.kit 49% · downloader 43% · worm 56% |
| ↳ **▶ 다음에 할 일 (2026-09-20 · A·B 완료, C 규칙 둘 완료)** | ~~**A** `cleartext-credentials` HIGH → MEDIUM~~ — **57교시 완료**(사용자 확인 후). HIGH 표본 6,120 → **12**(form-action-ip 9 · data-uri-document 3), 발견 수 22,112 그대로 (§12.38). ~~**B** `webshell-signature` 가 본문도 보게~~ — **58교시 완료.** 보이는 이름 ∧ 파일 업로드 칸. backdoor 0 → **42**/132 · 웹셸을 다루는 정상 글 16쪽 오탐 7 → **0** (§12.39). **C** 재현율 구멍 — 기준을 "발견 0건"이 아니라 **"공격 분류 발견 0건"** 으로 잰다(16,476개 · 67%). **59교시에 첫 규칙 `local-system-object`** → 13,398(54%) (§12.40). **60교시에 이름 없는 웹셸**(안전 모드 ∧ `drwx` ∧ 업로드 칸, `webShellPage` 확장) → 13,382 (§12.41). **62교시 `encoded-shellcode`**(`%u` 가 글이 아닌 값으로 풀림) → 13,240 (§12.43). **ransomware 323 은 분석 후 만들지 않음**(경찰 사칭 잠금 사기 키트 하나 — 보류 표의 browlock 줄, §12.44). **trojan 의 `Loading...` 66 도 분석 후 만들지 않음**(넓히면 오탐 원인이던 모양, 좁히면 키트 하나 — 보류 표, §12.45). 채굴 4,007 은 이름·호스트 목록 방식밖에 없어 하지 않는다 → **C 마무리**. 중복은 대표 호스트로 묶어 함께 보고한다. ~~**D** 스크립트 규칙이 데이터 블록까지 봄~~ — **61교시 완료.** 정상 텔레그램 봇 라이브러리의 GitHub 코드 화면 2쪽이 `exfil-channel` HIGH → 0. 판정을 `ctx.scriptCode` + `scriptText()` 로 옮겨 세 규칙이 공유, 데이터셋·음성·코퍼스는 전후 같음 (§12.42). |
| ↳ **측정 도구 다시 만드는 법** | 스크래치패드는 사라질 수 있다. Go 로 `archive/zip` 을 열어 `.json` 만 읽고, `{"strings":[…]}` 를 `strings.Join(…, "\n")` 으로 이어 `scanner.ScanURL(html, "")` → 분류(zip 이름 `html.<분류>_1.zip`)별로 표본 수·발견 있음·HIGH 있음·규칙별 발동 표본 수를 센다. 저장소 밖 모듈에서 `replace github.com/suseong41/sha => <저장소 복사본>` 으로 붙인다. 되살린 HTML 은 **디스크에 쓰지 않는다.** 전체 24,636개가 약 50초. 증거 문자열은 90자로 잘라 3개씩만 찍는다. **58교시 도구**(`ctas/ws`): 토크나이저만 써서 시그니처·표지가 나온 **자리**(title · textarea · text · raw · attr · comment)를 표본별로 세고 후보 조건을 나란히 비교한다(`ws dataset <dir>` · `ws perfile <html…>`). **음성 표본 16쪽**(웹셸을 다루는 정상 글)의 출처는 DISCUSSION §12.39 — 다시 받을 때도 **웹셸 배포 사이트는 받지 않는다**. **음성 표본 2**(`ctas/neg2`, 텔레그램 API 를 다루는 정상 GitHub 페이지 4쪽 — 출처는 §12.42). **62교시 도구**(`ctas/spray`): 실행 스크립트의 `%u` 구간을 재고, `spray escaped <html…>` 로 **실제 페이지의 보이는 글을 JS `escape()` 로 숨긴 합성 음성**을 만든다(300자 조각, 서로게이트 짝 유지). **ransomware 분석 도구**(`ctas/ransom`): 진단명(`av_detection`)·제목·iframe 모양·인라인 스크립트 앞부분 집계, `ransom behav zip …` · `ransom behav files 이름 …` 로 가두기 행동을 세고, `ransom drill 압축파일` 로 행동이 있는 페이지를 진단명·제목별로 묶는다 |
| **가려진 리다이렉트(`Loading...` 키트)** | **2026-09-20 분석 후 만들지 않음(사용자 결정 — "오탐 원인이니 기록만 하고 넘긴다").** trojan 의 `Loading...` 66건 = 장치 지문 25가지를 XOR 해시해 `&utm_content=` 에 붙여 16진수로 숨긴 주소로 보내는 광고 트래픽 관문(`clickverify=1`), 한 키트. 후보 셋: 문자열 숨김(≥16 연속) 737개·164계열이지만 MEDIUM(정상 이메일 가리기와 같은 수법) · 숨긴 주소 ∧ 이동(같은 스크립트) 140개·13계열이지만 **"같은 스크립트에 있을 뿐"은 `obfuscated-eval` 에서 이미 버린 모양** · 같은 식으로 좁히면 66개·1계열(시그니처). 정상 71·음성 20 은 셋 다 0. **다시 볼 조건**: JS 를 파싱해 값의 흐름을 따라갈 수 있게 되면 (§12.45) |
| **브라우저 잠금 사기(browlock)** | **2026-09-20 분석 후 만들지 않음(사용자 결정 — "핵심은 HIGH").** ransomware 323개 = 경찰 사칭 잠금 사기 **키트 하나**(6개 언어, 인라인 스크립트 95%+ 동일, 호스트 37곳). 가두기 넷(나가기 · 오른쪽 클릭 · 선택 · 드래그) 동시 = 323 · 그 밖 악성 0 · 정상 0 이지만 한 키트의 시그니처이고, 온라인 시험 같은 정상 모양을 못 쟀고, 만들어도 MEDIUM 이다. 같은 주소 iframe 75개는 정상(1)과 키트(75) 사이를 다른 악성(2~20)이 채워 경계 근거가 없다. **다시 볼 조건**: 다른 잠금·기술지원 사기 계열 1개 이상 + 복사 방지·나가기 경고가 있는 정상 페이지 음성 (§12.44) |
| ~~foster parenting~~ | **2026-09-17 측정으로 닫음** — `x/net/html` 을 대조군으로 표 6경우를 재니 우리 판정이 전부 일치했다. foster parenting 은 노드의 **자리**를 바꾸지만 폼 소속은 **form 요소 포인터**로 정해지고, 우리 규칙은 자리가 아니라 소속을 묻는다. 회귀 3건을 `differential_test.go` 에 고정 |
| **단일 체계 위조(`аррӏе`)** | **2026-09-17 측정 후 보류 유지 — 만들지 않는다.** C-TAS 918개의 punycode 63개가 **전부 한글 단일**(키릴 0 · 그리스 0), 정상 코퍼스·실측 호스트 2,226개에는 punycode **0개**. 대상도 0건이고 **오탐을 잴 음성 표본도 0건**이라 규칙 추가 절차 2·3번을 지킬 수 없다. **다시 볼 조건**: 새 표본에서 **키릴·그리스 단일 체계 라벨이 1건이라도** 나오면 그때 만든다. 곁가지: punycode 63개의 TLD 는 `.com` 45 · `.me` 13 · `.co` 4 · `.net` 1 — "한글 라벨인데 한국 TLD 가 아니다"도 신호가 될 수 있으나 정상 표본이 0건이라 오탐률을 못 잰다 (§12.36) |
| ~~eTLD+1 표 확장~~ | **2026-09-17 측정 후 24 → 39개.** 호스트 3,141개를 PSL(`x/net/publicsuffix`)과 대조해 어긋난 555개의 접미사만 넣었다. 대부분이 무료 호스팅(github.io 240 · vercel.app 214 · netlify.app 47 · framer.app 12 — 전부 C-TAS 악성 도메인). 1건짜리와 지역별로 갈라지는 것(`execute-api.<지역>.amazonaws.com`)은 뺐다 (§12.35) |

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

**CI `vuln` 잡** (54교시 뒤) — `govulncheck@v1.8.0 ./...` 를 푸시·PR·**주간 schedule** 에서. 취약점은 코드가 그대로여도 새로 알려진다.
`setup-go` 가 go.mod 버전을 깔므로 새 패치가 취약점을 고치면 이 잡이 실패해 go.mod 을 올리라고 알린다(의도된 빨간불).
도구는 고정해도 취약점 목록은 매번 온라인에서 받는다. GitHub Actions 첫 실행 `No vulnerabilities found.` (2026-09-16).
검증: 지금 코드 종료 코드 0 · 1.24.6 바이너리 대조군 26건 비0 · actionlint 0 / `runs_on` 오타 대조군 1.
**측정 실수 둘**: 첫 대조군은 go.mod 이 1.27.1 을 요구해 1.24.6 빌드가 안 된 것(무효) · "actionlint 문제 없음"은
git 저장소가 아니라 시작도 못 한 걸 `| head &&` 가 가렸다(§6 표에 기록). `go run` 은 govulncheck 의 종료 코드 3 을 1 로 바꾼다.
사용자가 붙인 블록이 저장되지 않아 커밋에 빠졌다 → 위임받아 내가 넣음(CR 0 · actionlint 0).

**55교시** — 보류 항목 **foster parenting 을 측정으로 닫았다.** 대조군은 `golang.org/x/net/html`(같은 명세의 다른 구현, 스크래치패드에서만 사용).
표가 폼과 입력을 갈라놓는 6경우(입력이 표 밖으로 · 폼만 표 안 · 폼 안의 표 · 셀 안 · 닫은 폼 뒤 입력 · `form=` 원격)에서
**우리 판정이 참조 파서와 전부 일치.** 이유: 브라우저도 자리가 아니라 **form 요소 포인터**로 묶고, 우리 `openStack` 도 같은 포인터를 들고 있다.
`differential_test.go` 에 3건 고정 — `</table>` 에서 포인터를 버리는 변이를 넣으면 `표안폼_입력은표뒤` 가 실패한다(확인).
**재면서 드러난 다른 것**: `<svg>` 안의 `svg:form`·`svg:input` 은 HTML 폼이 아닌데 우리는 HIGH 를 준다(오탐).
외래 콘텐츠는 35교시에 "다시 논의하지 말 것"으로 닫은 항목이라 **결정을 뒤집지 않고 비용만 기록**한다(코퍼스 21쪽 중 svg 7쪽·146회, 그러나 form+password 동반은 0건).
`<template>` 안의 폼도 잡는데, 스크립트가 복제하면 진짜 폼이 되므로 그대로 둔다.
**HIGH 규칙은 8종이 아니라 10종**이었다(코드에서 다시 셈) — 보류 표의 숫자가 낡아 있었다.

**56교시** — eTLD+1 표 24 → 39개. **무엇을 넣을지는 기계적이지 않다 — 재서 골랐다.**
코퍼스·실측 71쪽 안의 호스트 + sites.txt + C-TAS 도메인 918개 = **3,141개**를 `x/net/publicsuffix` 와 대조 → **555개 어긋남**.
쏠림이 뚜렷했다: `github.io` 240 · `vercel.app` 214 · `netlify.app` 47 · `framer.app` 12 (**전부 C-TAS 악성 도메인**).
지금 판정으로는 `victim.github.io` 와 `attacker.github.io` 가 같은 조직이라 **비밀번호가 옆 계정으로 가도 HIGH 가 안 났다**(미탐).
PSL 의 사설 구역이 정확히 이 목적이다 — 묻는 것은 "같은 출처인가"가 아니라 **"우리가 통제하는가"**(§12.2 와 같은 기준).
**양방향 측정**: 코퍼스 21쪽 발견 수 **변화 없음**(오탐 증가 0) · 놓치던 3경우가 HIGH 로 잡힘 · 같은 계정끼리는 그대로 0건.
1건짜리(`edu.sy`·`iki.fi`·`my.id`·`s3.amazonaws.com` 등)와 지역마다 달라지는 접미사는 **뺐다** — 손으로 관리하는 표라 근거 있는 것만.
테스트에 `{"victim.github.io","victim.github.io",true}` 를 함께 넣었다: "남남으로 본다"만 시험하면 **전부 남남으로 보는 코드**도 통과한다.
변이 검사 5건(개별 접미사 제거 · 표 비우기) 전부 잡힘.

**57교시** — `cleartext-credentials` HIGH → **MEDIUM**. **등급도 출력 계약이다 — 바꾸기 전에 테스트로 붙잡는다.**
C-TAS 에서 걸린 건 피해 사이트의 http 로그인 폼이었다(§3 과 충돌, §12.37). 남의 서버로 보내는 공격자는 `cross-origin-password-form`(HIGH)이 따로 잡는다 — 두 경우를 돌려 확인.
스크래치패드에서 등급만 바꿔 보니 **테스트 0개 실패** — 아무도 등급을 붙잡고 있지 않았다. 그래서 **양성 표본 전부**에 `f.Severity != Medium` 을 단언했다(테스트는 이번부터 내가 쓴다, §1).
변이 3건 전부 잡힘: `Low`(정확한 값을 단언해야 한다 — "HIGH 아님"은 LOW 도 통과) · 규칙이 안 뜸(`findFirst` 의 `ok` 가 빈 루프의 통과를 막는다) · `http://` 경로만 HIGH(4 실패 2 통과 — 표본 하나였다면 절반 확률로 놓친다).
재측정: HIGH 표본 **6,120 → 12**, 발견 수 22,112 그대로. 바뀐 계약: `-min high` 에서 http 로그인 폼만 있는 페이지의 종료 코드 1 → 0 · API `severity` 가 `"MEDIUM"`. CI 스모크 영향 없음(악성 표본의 HIGH 3건은 다른 규칙). 651 테스트.

**58교시** — `webshell-signature` 를 **보이는 이름 ∧ 파일 업로드 칸**으로. **이름은 언급일 뿐이다 — 웹셸은 화면(방문자에게 쥐여 주는 능력)이 증명한다.**
정상 71쪽에는 웹셸 이름이 0번이라 **그 코퍼스로는 오탐을 잴 수 없었다** → 웹셸을 **다루는** 정상 글 16쪽을 따로 받았다(배포 사이트 접속 안 함, 스크래치패드 `ctas/neg`).
지금 규칙(스크립트 안)은 backdoor 0/132 인데 **다루는 글 7쪽에 HIGH** — GitHub 코드 화면 JSON 속 파일 경로, 블로그 스크립트 속 글 주소. 본문에 이름만 → 11쪽 오탐 · 이름 ∧ 서버 정보(uname 등) → 2쪽(출력을 인용한 글 — **글이 옮겨 적을 수 있는 것은 가르지 못한다**) · **이름 ∧ 업로드 칸 → 42/132 · 0쪽**.
구조: 페이지 단위(`Check` 는 기록, `Finish` 가 판정 — `phishingFlagPage` 와 같은 모양). 보이는 글 = `Raw` 아닌 텍스트. 한 페이지 한 건.
테스트는 내가 썼다(15경우 + 위치 · inject/class/fuzz 조각 · `malicious_sample.html` 11~14줄을 **같은 줄 수로** 교체해 뒤쪽 위치 보존). 사용자 구현은 검증본과 코드 동일(주석만 사용자 표현). 변이 7건 전부 잡힘.
재측정: HIGH 표본 12 → 55, 다루는 글 0, 정상 0. 660 테스트.

**59교시** — `local-system-object` (HIGH execution). **드로퍼는 방문자 PC 를 향한다 — 웹 페이지가 쓸 일이 없는 객체를 찾는다.**
C 의 기준을 "발견 0건"(2,520)에서 **"공격 분류 발견 0건"**(16,476 · 67%)으로 바꿨다 — hardening·supply-chain 만 있는 표본도 공격엔 침묵한 것이다. 흔적 32가지를 정상 71쪽·다루는 글 16쪽과 나란히 세서, 정상에도 나오는 것(`ActiveXObject` 자체 · `</html>` 뒤 스크립트 · 숨긴 iframe · `eval`·`document.write`)은 버렸다.
남은 것: `WScript.Shell` · `Shell.Application` · `Scripting.FileSystemObject` · `ADODB.Stream` — 공격0건 3,078 · 정상 0 · 다루는 글 0. 대표 호스트 1,676곳·드로퍼 40종(퍼진 감염). **코드 블록만**(빈 type · JS · VBScript) — GitHub 코드 화면의 `application/json` 블록을 받아 둔 페이지에서 확인했다. 한 페이지 한 건.
테스트는 내가 썼다(15경우 + 위치 · inject/class/fuzz). 본문·스타일 음성을 **코드 블록 뒤에** 둬서 "코드 표시가 `</script>` 뒤까지 남는" 변이를 잡았다. 변이 9건 전부 잡힘 — 처음 2건은 **치환이 안 된 채** "살아남음"으로 찍혔다(§6).
사용자 구현에서 `range localHotst` — 자동완성이 기존 변수를 골랐다(§6). 양성 전부 0 · **코퍼스 2쪽 HIGH** · 주입 21쪽 미탐으로 잡혔고 한 단어 고쳐 초록.
재측정: 공격 분류 발견 0건 16,476 → **13,398(54%)** · HIGH 표본 55 → 3,792 · 정상 0. 683 테스트.

**60교시** — 이름 없는 웹셸. **이름을 몰라도 화면이 하는 일은 같다 — 서버 환경을 보여 주고, 파일을 권한째 늘어놓고, 올리게 해 준다.**
`webShellPage` 를 넓혔다(새 규칙 아님, 한 페이지 한 건, 이름 우선): PHP 안전 모드 상태(`safe_mode` · `safe-mode`) ∧ `drwx` ∧ 업로드 칸 → "웹셸 화면: 이름 모름". backdoor 42 → **58**, 순증가 16개는 전부 `Locus7Shell`·`x2300`(이름 바꾼 c99 변종, 15개 사이트) — 목록에 이름을 더하지 않고 구조로 잡았다.
표지는 재서 줄였다: 서버 정보 넷 = `safe_mode` 표기 둘(48) > `uname` 만(45), 윈도우식 `safe mode` 는 0. **`drwx` 를 빼면 95** 지만 그 음성(uname 을 인용한 포럼 + 첨부 칸)을 재 보기 전엔 넓히지 않는다 — 세 항이 각각 재지 못한 음성 하나씩을 막는다.
변이 8건 전부 잡힘. 처음 구현에서 **동등 변이**("이름 찾으면 표지 안 봄")가 살아남아, 그 형태를 구현으로 삼았다 — 기존 줄을 안 건드림. 사용자 구현의 `"sfade-mode"`(문자열 속 오타)는 하이픈 표기 경우만 실패하는 **모양**으로 찾았다(§6). 700 테스트.
같은 날 **첫 연구(파이썬 스캐너, `/Users/suseong/test/message.txt`) 검토** → DISCUSSION §9.8: 신호 목록은 대부분 맞았고 실패는 추출(정규식)·결합(합산) 두 층. 결함은 스크래치패드에서 import 만 해서 재현했다.

**61교시** — 판정은 한 곳에. **59교시에 `localObjectRule` 안에만 넣은 "코드 블록만" 판정이, 같은 `scriptText()` 를 쓰는 `exfil-channel`·`obfuscated-eval` 에는 없었다.**
재현: GitHub 코드 화면 모양(`<script type="application/json">`)에 텔레그램 주소 → HIGH. 실제로도 **정상 텔레그램 봇 라이브러리 코드 화면 2쪽이 HIGH**(github.com 만 접속, 스크래치패드 `ctas/neg2`).
고침: `Context.scriptCode` 를 `<script>` 시작 태그에서 정하고 `scriptText()` 가 확인 → 세 규칙이 공유, `localObjectRule` 의 자체 판정은 지웠다(테스트로는 못 잡는 **중복** — 검토로 짚었다).
측정: 데이터셋·다루는 글 16·실측 50·코퍼스 21 전후 같음(잃은 탐지 0). 테스트 `TestScriptRulesSkipDataBlocks`(음성 5 · 양성 3), 변이 5건 전부 잡힘 — 순서 테스트 둘(`코드블록뒤JSON`·`JSON뒤코드블록`)이 "시작 태그마다 다시 판정"을 붙잡는다. 709 테스트.

**62교시** — `encoded-shellcode` (HIGH execution). **비율이 아니라 있다·없다 — 경계는 분포의 틈에서만(§3).**
exploit kit 은 셸코드를 `unescape("%uXXXX…")` 로 숨긴다. 그런데 옛 `escape()` 는 **한글도** `%uB85C` 처럼 적는다 → 음성이 필요했는데 정상 91쪽엔 `%u` 가 0개 → **실제 글(한·중·일·아랍·힌디 11쪽)을 `escape()` 로 숨긴 합성 음성 566조각**을 만들었다.
가설 넷: 연속 ≥10(글 185조각 오탐) → 한 문자 체계 90% 미만(일본어 가나+한자·아랍어에서 오탐) → 유니코드 문자 분류 90% 미만(오탐 0 이지만 **90% 가 셸코드 분포 80~95% 한가운데**) → **글이 아닌 값(Cc·짝 없는 Cs·Co·Cn)이 하나라도** — 글은 전부 정확히 100% 글자였다. 썰매 목록(`%u0c0c` 등)은 더할 것이 없어 뺐다(2건, 이미 다른 규칙). 서식 문자(Cf: RLM·ZWJ·ZWSP)는 실제 글에 있어 글로 친다. `unescape()` 처럼 **소문자 `%u` 만**.
테스트는 내가 썼다(15경우 + 위치 · inject/class/fuzz). 변이 11건 전부 — "끝에 남은 서로게이트"는 **변이를 짜다 빈 경우를 발견해** 더했다. 사용자 구현은 검증본과 코드 동일.
재측정: exploit.kit **154건**, 공격 분류 발견 0건 13,382 → **13,240**, HIGH 표본 3,808 → 3,955, 음성 전부 0. 732 테스트.
**내 측정 실수 셋**(§6): 빌드 실패인데 옛 바이너리가 돎 · zsh `$files` 안 쪼개짐 · `go test` 가 통과 출력을 숨겨 잘못 결론냈다가 철회.

**62교시 뒤 — ransomware 분석(규칙 없음)**: 323개는 경찰 사칭 **브라우저 잠금 사기 키트 하나**(진단명 `JS.Fakeransom` 등, 6개 언어). 가두기 넷 동시 = 323 · 그 밖 0 · 정상 0 이었지만 **표본 수가 아니라 계열 수가 일반화를 말한다** — 한 키트 · 정상 모양(온라인 시험) 미측정 · 만들어도 MEDIUM 이라 만들지 않았다(사용자: "핵심은 HIGH"). §12.40 의 "iframe 하나뿐"은 틀린 기록이라 정정(실제로는 같은 주소 75개).

**62교시 뒤 — 배포 전 기록 점검(2026-09-20)**: ① **`.dockerignore` 가 동작하지 않았다** — 맨 앞 `*` 가 없어 `!` 가 되살릴 것이 없었다. 받아 둔 `testdata/live` 50쪽이 빌드 컨텍스트로 갔다. 고친 뒤 컨텍스트 ~59MB → **62.75kB**(§12.30 정정, §6 함정). ② **HIGH 11종의 실측 근거 표가 없었다** → §12.46. 지금 코드로 다시 재니 HIGH 표본 3,955 그대로인데 **확인된 것은 5종뿐**이고 `exfil-channel` 은 0건 — 오탐만 확인됐고 재현율은 미측정이다. 실측 쪽수 표기를 50 → **45**(내용이 있는 쪽)로 정정.

**63교시** — `version` 패키지(0.1.0) · CLI `-version`. **버전은 한 곳에서만 말한다.**
CLI 와 서버는 다른 `package main` 이라 서로를 import 할 수 없다 → 작은 패키지 하나를 둬 셋(CLI·서버 로그·이미지 라벨)이 같은 값을 읽게 했다. **이미지 라벨은 저장소에 적지 않는다** — 배포 워크플로가 태그에서 붙인다(같은 숫자가 두 번 적히면 드리프트가 시작된다). 태그는 `v0.1.0`, 상수는 `0.1.0` — 형식 검사가 `v` 를 붙이는 실수를 잡는다.
`-version` 분기의 **자리**가 핵심: `Parse` 뒤 · `NArg` 검사 앞. 앞이면 플래그를 못 읽고, 뒤면 파일을 안 줬다고 2로 끝난다.
테스트는 내가 썼다(3개). 변이 5건 전부 잡힘 — 판정을 NArg 뒤로 · stdout→stderr · 버전 없이 이름만 · `return 0` 빠짐 · 상수에 `v`. 735 테스트.

**64교시** — `GET /healthz`. **스캔 경로와 성질이 다른 요청은 다르게 다룬다.**
`{"status":"ok"}` 만 — **버전도 안 담는다**(인증 없는 경로에서 무엇이 도는지 알려 줄 이유가 없다). 밖으로 나가지 않고 **로그도 남기지 않는다**(프로브가 초당 한 번 두드리면 로그가 그것뿐이 된다). `h *handler` 의 메서드가 아니라 **그냥 함수** — 수집기도 로거도 안 쓴다는 걸 코드가 드러낸다. 패턴에 `GET` 을 적어 나머지 메서드는 405(HEAD 는 GET 에 딸려 온다).
compose `healthcheck` 에는 여전히 못 넣는다(scratch 에 셸·curl 없음) — 쓰는 쪽은 **밖에서 두드리는 것들**(k8s httpGet · LB · nginx 업스트림). INTEGRATION.md 6절의 "상태 확인 경로가 없다"를 갱신.
테스트는 내가 썼다(2개). 변이 6건 전부 잡힘 — 패턴에서 `GET` 뺌 · 200→204 · 본문에 버전 얹음 · `status` 철자 · **모든 요청을 로그로 남기는 미들웨어 추가** · 보안 헤더 밖으로. 737 테스트.
**실제 이미지로 확인하다 빌드가 깨진 걸 발견**: 63교시에 더한 `version` 이 `.dockerignore` 허용 목록에 없었다 — 허용 목록은 **기본 거부**라 패키지를 더하면 목록도 고쳐야 한다(어제까지는 목록이 안 걸러서 드러난 적이 없었다). `!version` 한 줄 추가 후 컨테이너 확인: `/healthz` 200·16바이트·헤더 붙음 · HEAD 200 · POST 405 · 없는 경로 404 · **요청 네 번 뒤에도 로그는 `listening` 한 줄뿐** · 실제 스캔(example.com) 200. **CI 는 `docker build` 를 하지 않는다** → 66교시에 단계로 넣는다(배포하는 날 처음 아는 부류의 실패).
**65교시** — 동시 스캔 상한(`DefaultMaxScans = 4` · `-max-scans`). **재고 나서 정한다.**
측정 자리: 도커 망을 **`203.0.113.0/24`(문서용 공인 대역)** 로 만들어 **SSRF 방어를 켠 채** 가짜 대상에 닿게 했다(바깥 접속 0).
잰 것: 5MB 페이지 **한 건 = 약 50MB** · 응답 시간은 동시 수에 선형 · **256MB 제한에서 동시 9 까지 살고 10 부터 OOM**(그 순간 요청 전멸).
설계 세 판을 재서 골랐다: 즉시 503(동시 16에서 **64건 중 4건만 성공**) · 계속 기다리기(전부 성공하나 평균 11초) · **2초 기다렸다 503**(전부 성공 0.89초, 폭주는 2초 만에 거절). 슬롯을 **가져오기 전에** 잡아서 대기 중에도 메모리가 안 는다(4KB 본문만 든다).
**48교시 테스트가 내 설계 결함을 잡았다** — `select` 는 준비된 갈래가 여럿이면 **무작위로** 고른다. 자리 잡기만 있는 바깥 `select` 를 두고 취소·시간 초과는 안쪽에서만 따지게 고쳤다.
테스트는 내가 썼다(6개). 변이 8건 전부 잡힘. 744 테스트. 실제 이미지 재측정: 동시 256 요청에도 OOM 없이 112MB.


**66교시** — 배포 준비: LICENSE · NOTICE · CI 이미지 빌드 · 릴리스 워크플로. **남에게 넘기려면 코드 주변이 필요하다.**
LICENSE 는 **문안만** 둔다 — GitHub 라이선스 인식은 파일 전체를 표준 문안과 대조해서, 뒤에 설명을 붙이면 `Other` 로 잡힌다. 제3자 고지(gTest = BSD-3-Clause)는 `NOTICE` 로 뺐다.
CI 에 `image` 잡 추가 — 스모크는 **`/healthz` 만** 두드린다(바깥을 스캔하면 네트워크로 흔들리고, **흔들리는 빨간불은 무시당한다**). 시작 로그의 `"version"`·`"max_scans"` 도 검사 → 옛 이미지면 잡힌다.
멀티아키는 **에뮬레이션이 아니라 크로스 컴파일**: `--platform=$BUILDPLATFORM` + `GOOS/GOARCH=$TARGETOS/$TARGETARCH` → amd64·arm64 합쳐 **6초**(QEMU 면 분 단위).
`release.yml` 순서에 뜻이 있다: ① 태그 vs `version.V` 대조(다르면 아무것도 하기 전에 멈춤) → ② 테스트(**푸시한 이미지는 되돌릴 수 없다**) → ③ 빌드·푸시(라벨 버전은 태그에서).
워크플로 파일은 사용자 요청으로 **내가 직접 넣었다**(구현 코드는 여전히 사용자가 친다). 확인: YAML 파싱 + **대조군**(깨뜨린 YAML 은 실패) · 스모크를 로컬에서 그대로 실행 · 태그 대조 스크립트 로컬 시험(v0.1.0 통과 / v0.2.0 멈춤) · 단일·멀티아키 빌드 실측.
**배포 완료 (2026-09-20)**: `v0.1.0` 태그 → Release 성공 → **`suseong41/suseong-html-analyzer:0.1.0`·`:latest`**(당시 이름, amd64·arm64, 3.4MB). 받아서 확인함 — 라벨·`/healthz`·실제 스캔·시작 로그 전부 정상.

**67교시** — 식별자를 `sha` 로 통일(사용자 결정). **이름을 바꾸면 문장이 거짓이 된다.**
대문자 가능 여부를 먼저 쟀다: Docker 이미지 **불가**(`must be lowercase`) · Go 모듈은 가능하나 프록시가 `!s!h!a` 로 이스케이프 · GitHub 저장소는 가능. **한 곳이 반드시 소문자면 전부 소문자**가 어긋남 0 → 식별자 `sha`, 대문자 SHA 는 읽는 자리에만.
치환은 `git grep -l ... | xargs sed` 한 줄(추적 파일만 — `.git`·코퍼스 HTML 안 건드림). 31개 파일, 744 테스트 그대로. 실행 파일 이름은 **모듈 경로 끝 조각**이라 저절로 `sha`.
**함정**: 일괄 치환이 **이력 문장까지** 바꿔 "옛 이미지 …:0.1.0" 이 존재하지 않는 이름을 가리키게 됐다 — README·§12.50·§14·교시 요약 5곳을 되돌렸다. 스크래치패드 측정 도구의 `replace` 경로도 함께 고쳤다.
옛 이미지는 **지웠다**(위 2절 근거). GitHub 은 옛 저장소 주소를 리다이렉트하지만 **Docker Hub 에는 그런 기능이 없다** — 옛 이름으로 오면 그냥 not found 다.

**68교시** — my_homepage 연동 · README 정리. **계약을 남의 페이지에서 지키는 일.**
바꾼 것 셋(`docker-compose.yml` · `nginx/nginx.conf` · `html/index.html`), **212줄 추가 · 삭제 0**. 서비스는 `build:` 가 아니라 **`image: suseong41/sha:0.2.0`**(버전 고정) · CSP 는 **Report-Only**(페이지가 아직 인라인 스크립트·onclick 을 씀) · 결과는 **`textContent` 만**.
검증은 스택 통째로(nginx + busybox api + 배포 이미지, 자체 서명 인증서). **대조군 둘이 핵심**: 헤더를 믿는 설정에서 IP 8개가 전부 통과해야 앞의 429 가 "위조 무시"의 증거가 되고, `innerHTML` 대조군이 요소 2개를 만들어야 우리 쪽 0개가 뜻을 갖는다. 응답 6종 화면·버튼 잠김 해제까지 확인.
**브라우저로는 못 봤다**(jsdom 은 요소 생성까지만). 기존 페이지의 `innerHTML`·`marked.parse`·`onclick` 은 그대로 — CSP 를 켜려면 그것부터.
곁가지: README 를 **존댓말로 통일**하고 내부 문서 참조(§번호)를 걷어냈다(`docs/INTEGRATION.md` 링크는 남김). **gTest 63개 + NOTICE 삭제**(사용자 결정) — 이력에는 남는다.

**69교시** — my_homepage 의 api 를 FastAPI → **Go 표준 라이브러리**로 이관(저장소 밖 작업). **계약을 먼저 고정한다.**
파이썬 판의 응답을 **골든 파일**로 박고(표본은 실제 티스토리 RSS·GitHub 응답, 갈래를 채우려 포크 하나·별 하나만 손봄), 같은 값이 나오는지 대조하는 테스트를 먼저 깔았다. 이미지 239MB → 9.8MB · 메모리 37MiB → 7.9MiB · **의존성 16개 → 0개**.
잡힌 것 셋: `package apigo`(에디터가 폴더 이름으로 지음 — 실행 파일은 `package main`) · **태그 오타 둘**(`decription` 은 키가 틀리게 나가고 `laguage` 는 값이 비어 나온다 — 증상이 어느 쪽 태그인지 알려 준다) · `&BUILDPLATFORM`.
변이 9건 중 8건 잡힘. 남은 하나는 **코드가 군더더기**였다 — Go 의 base64 디코더는 `\r`·`\n` 을 원래 무시한다(재서 확인하고 그 줄을 지웠다).

**70교시** — 진행 상황 **흘려보내기**(NDJSON). **흘려보내기는 서버 혼자 정하지 못한다.**
SSE 를 안 썼다 — `EventSource` 는 GET 만 되어 `GET /api/scan?url=…` 이 생기고, 그건 §12.29 의 결정(폼·이미지로 못 부르게)을 되돌린다. 같은 POST 응답을 줄 단위 JSON 으로 흘린다. `Accept: application/x-ndjson` 없으면 **완전히 이전과 동일**.
단계는 **둘뿐**(가져오기·파싱). 주소 판정·집계는 따로 못 재므로 만들지 않았다. 흘리기 시작하면 상태 코드를 못 바꾸므로 그 뒤 실패는 `error` 줄, 거절(503)은 흘리기 전이라 상태 코드.
**두 번 틀렸다**: `Microseconds()` → 화면에 "파싱 9497ms"(실제 스캔에서만 드러남 → **단계 합 ≤ 전체** 단언 추가) · **nginx `proxy_buffering` 이 켜져 있어 한 번에 도착**(컨테이너 직접 호출로는 안 드러남 → `/api/scan` 에만 끔).
테스트는 내가 썼다(7개). 변이 6건 전부 잡힘. 751 테스트. 화면은 `mon47-web` 의 로그 패널 껍데기만 가져왔다 — 그쪽 로그는 **하드코딩 연출**이었다.

**71교시** — `sri-missing` MEDIUM → **LOW**(사용자 물음에서 시작). **웹의 기본 상태는 신호가 아니다.**
쟀다: 악성 66.5% · 정상 코퍼스 67% · 실측 58% — **악성과 정상을 가르지 못한다.** 게다가 정상에서 MEDIUM 의 93%·87%가 이 규칙 하나였다(발견 116건 중 70건). 잃는 것도 쟀다 — 악성의 33.1%(8,145)가 "sri-missing 이 유일한 MEDIUM" 이지만, 그건 **정상과 구별되지 않는 이유로** MEDIUM 이었다.
**정하려다 더 큰 구멍을 찾았다**: MEDIUM/LOW 의 경계가 글로 없었다("HIGH 는 악성 행위에만"만 있었음) → §3 에 네 칸의 정의를 적고, **`TestEveryRuleSeverity` 로 25종 전부의 등급을 못 박았다**(57교시엔 한 종뿐이었다).
문맥으로 가르는 안(버전 고정된 주소만 MEDIUM)은 버렸다 — "고정됨"을 URL 패턴으로 **추측**해야 하고, 위험의 크기는 같다(다른 건 조치 가능성이지 심각도가 아니다). 외부 스크립트 298개 중 **73%가 고정 안 됨** = integrity 를 붙일 수조차 없다.
**테스트가 계약 변경을 잡았다** — `-min medium` 에 `sri-missing` 을 기대하던 CLI 테스트가 빨개졌다. 지금 사실로 고쳤다(정상은 아무것도 안 나옴 / 악성은 HIGH 3·MEDIUM 2).
재측정: 실측 45쪽의 MEDIUM **74 → 4건**(전부 `javascript-url`), 발견 총수·규칙별 수는 그대로. 753 테스트.

**72교시** — my_homepage 의 CSP 를 **실제로 켬**(Report-Only 제거). **켤 수 없는 정책은 정책이 아니다.**
막던 것을 치웠다: 인라인 `<script>` 180줄 → `assets/main.js`(DOM API 로 다시 씀, `innerHTML` 은 README 모달만 남음) · `onclick` → 위임 · 템플릿의 `style=` → `el.style.x`(**CSSOM 은 CSP 가 안 막는다** → `style-src` 에서 `'unsafe-inline'` 제거) · CDN `marked` → **직접 호스팅 + 18.0.13 고정**. index.html 266 → 88줄.
`img-src` 만 `https:` 로 넓다 — README 배지가 여러 호스트에서 오고 이미지는 실행되지 않는다.
**확인은 헤드리스 Chrome 으로**(jsdom 은 CSP 를 강제하지 않는다) — **로컬** 두 페이지 위반 **0건**, 카드가 그려짐 = 스크립트가 돌았다는 증거.
**배포 뒤 운영에서만 위반 1건** — Cloudflare 가 끼워 넣는 Web Analytics 비컨(`static.cloudflareinsights.com`). 원서버 HTML 에는 없고 **`Accept: text/html` 이 붙은 요청에만** 삽입돼 맨 `curl` 로는 안 보였다. 허용하려면 받는 곳(`script-src`)과 보내는 곳(`connect-src`) **두 호스트**를 열어야 해서 **자동 삽입을 껐다**(사용자 결정). 재확인 두 페이지 0건. **켜기 전까지 저장소에 없는 제3자 스크립트가 돌고 있었고 몰랐다** — 정책은 막기도 하지만 무엇이 들어 있는지 세어 준다.
발견: 고정 안 한 CDN 주소가 **15.0.12 로 조용히 떨어지고** 있었다(18.x 에서 그 파일이 사라져서). 덤으로 자기 사이트의 `sri-missing` 이 사라졌다.
**실패 문구**: 봇 차단 사이트는 403 이 아니라 **무응답** → 우리 쪽엔 시간 초과로 보인다. "닿은 뒤의 실패(시간 초과·인증서·5MB)는 말하고, 닿기 전(이름 해석·차단)은 뭉뚱그린다" 로 선을 그었다 — 후자를 구별해 주면 내부 이름 실재 여부를 알려 주는 창구가 된다(§12.29). 테스트가 그 동일성을 단언. UA 위장은 넣지 않음(회피는 우리가 거부해 온 것).
화면(사용자 제안): `대상:` 줄 제거 · 발견/참고를 로그 안 `===== 결과 =====` 아래로 · 앞머리를 등급 이름으로. **결과 머리에는 시간을 안 붙인다**(서버가 재지 않은 단계다).

**73교시** — `POST /api/scan` 이 `{"html"}` 도 받는다 · my_homepage 에 악성 샘플 다섯. **받은 것을 검사한다.**
사용자 우려("악성 HTML 때문에 우리 페이지가 악성으로 분류되지 않겠는가")를 셋으로 갈랐다 — GitHub 은 낮음(`c99shell` 든 표본이 공개 저장소에 몇 주째, **증거가 이미 있었다**) · **세이프브라우징이 진짜 위험**(살아 있는 사이트를 크롤링한다) · 백신은 바이트를 본다.
규칙 셋: **정적 `.html` 로 두지 않는다**(JSON 으로만 — 크롤러가 따라갈 악성 페이지 주소가 없다) · **실제 시그니처를 담지 않는다**(우리 규칙은 구조로 판정한다) · **페이지에 인라인하지 않는다**(그러면 우리 사이트 자체가 그 페이지가 된다). **회피는 안 한다** — 조각내 숨기는 것은 72교시에 UA 위장을 거부한 것과 같은 짓이다.
표본은 **구조로만 발동하는 HIGH 다섯**. `exfil-channel` 은 호스트 목록 규칙이라 실제 주소를 적어야 해서 뺐다. 재서 확인: 우리 시그니처 17개 대조 **0건** · 주소는 `example.*`·`203.0.113.5` 뿐 · **가장 큰 요청 738바이트 → `client_max_body_size 4k` 그대로**(nginx 무수정).
API 는 **CLI 가 이미 하는 일**(`sha 파일.html <주소>`)이라 골랐다 — 정적 파일 안은 코드 변경 0이지만 규칙 ①을 정면으로 어긴다. 구현은 **갈림길을 한 곳에만**: 지역 변수 둘(`html`·`pageURL`) + 가져오기 블록을 `if req.HTML == ""` 로 감싸면 규칙·정렬·응답·스트리밍은 무수정. `url` 의 뜻이 갈린다(가져올 곳 ↔ 출처로 삼을 주소).
**로그가 거짓말할 뻔했다** — `html` 인데 `host=mybank.example.com` 이 남으면 접속한 것처럼 읽힌다 → `input` 필드(`url`·`html`). 테스트 7개(중심은 **`mustNotFetch`** — 48교시 `mustNotDial` 과 같은 자리), 변이 6건 전부 이름이 찍힌 진짜 실패로 잡힘. **769 테스트.**
**브라우저로 눌러 보고 나서야 보인 결함 둘**: `ms` 가 0이면 `omitempty` 가 지워 **"완료 — 전체 undefined ms"**(URL 검사에서는 영원히 안 보였을 것) · `start` 줄이 **접속한 적 없는 주소를 "요청"이라고** 찍었다(부른 쪽이 첫 줄을 정하게 고침).
대조군: 모달 소스는 `textContent` 라 요소 **0개**, 같은 문자열을 `innerHTML` 로 넣으면 **5개**. 곁가지 — `.sample-row { display: flex }` 는 브라우저 기본값 `[hidden] { display: none }` 을 **이긴다**(`.engine` 은 `display` 를 안 건드려 이 문제가 없었다).

1. **남은 보류**: HIGH 규칙 실측 — 데이터셋 도착 · 첫 측정(§12.37) · A(57) · B(58) · C 규칙(59 · 60 · 62) · D(61) · ransomware 분석(만들지 않음). **C 마무리.** 다시 볼 조건들은 보류 표에(단일 체계 위조 · browlock). 단일 체계 위조는 측정 후 보류 유지(다시 볼 조건은 보류 표에).

> **외래 콘텐츠(`<svg>`·`<math>`)는 보류로 결정했다** (35교시, DISCUSSION §12.14).
> 미탐 방향이지만 ① 트리 구성(네임스페이스·integration point)이 필요하고 ② 반쪽 구현은 반대 방향 오탐을 만들며
> ③ 브라우저로 검증할 수단이 없다. 트리 구성을 하게 되면 그때 함께 푼다. **다시 논의하지 말 것.**
2. `<input form="id">`·`<button form="id">` 원격 연결 — 스택으로는 불가, 트리 + id 인덱스 필요
3. 전체 트리 구성 — foster parenting, 삽입 모드 23개
4. punycode 호스트 — 정상 IDN과 구별하려면 혼합 스크립트 판정 필요
5. ~~eTLD+1 접미사 표 확장~~ — 39개 내장(56교시). 표에 없으면 마지막 두 라벨로 떨어져 **여전히 미탐 방향**이다

### 문서 갱신 규칙

규칙을 추가하거나 **등급을 바꾸면** **README(규칙 표) · DISCUSSION.md · Artifact 셋 다** 갱신한다.
문서가 뒤처지면 사용자가 지적하기 전에 먼저 알린다.
**틀린 숫자를 기록에 남기지 않는다** — 정정할 때는 정정 사실도 함께 남긴다
(예: DISCUSSION.md 9절의 "탐지 항목 9개 → 97개" 정정).
