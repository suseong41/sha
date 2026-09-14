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
old_c_files/   Go 전환 전 C++ 원본 (참조용, 수정하지 않음)
testdata/      jnu_main.html(정상) · malicious_sample.html(합성 악성) · spa_shell.html
               corpus/  실제 웹에서 curl 로 받은 정상 페이지 11쪽 (회귀 기준)
```

전신 프로젝트 두 개가 `../HtmlScanner`(C++ 13,838줄, 탐지 97종)와 `old_c_files/` 에 있다.
**둘 다 오탐/미탐의 바다가 되어 실패했다.** 그 원인 분석이 `DISCUSSION.md` 9절이다.

설계 논의 전문: [DISCUSSION.md](DISCUSSION.md) ·
Artifact: https://claude.ai/code/artifact/d20c0096-fb36-4afd-b57f-7c96ec67e558

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
6. **`go test ./scanner -run Corpus` 로 정상 12쪽 회귀를 확인한다** — 수가 늘면 오탐

2번으로 실제로 버린 규칙들: iframe sandbox 누락(GTM 정상 iframe), 스킴리스 URL(정상 2건),
`data:` 길이 임계값, form action 미지정.

---

## 5. 검증 명령

```bash
go build ./...          # _test.go 는 컴파일하지 않는다
go vet ./...            # 컴파일러가 안 잡는 것 (도달 불가 코드 등)
go test ./...           # 358개 (서브테스트 포함)
gofmt -l .              # 출력이 있으면 실패

# 퍼징 — 큰 변경 뒤에는 길게
go test ./tokenizer -run '^$' -fuzz FuzzTokenizer -fuzztime 5m
go test ./scanner   -run '^$' -fuzz FuzzScan      -fuzztime 5m

# 회귀 — 이제 테스트가 자동으로 잡는다 (손으로 돌릴 필요 없음)
go test ./scanner -run 'Corpus|Malicious' -v

#   TestCorpusNoFalsePositive   정상 12쪽 · HIGH == 0 · 총 26건
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

**도구가 못 잡은 실제 결함들** — 테스트가 유일한 방어선이었다:
`!` 누락(무한 루프) · `s = s`(자기 대입) · `" atob("` 앞 공백 하나 ·
`"iframe-snadbox-escape"` 오타 · `.gitignore` 의 `coverage.*` 가 `scanner/coverage.go` 를 삼킴 ·
`urlMixedContent` 죽은 함수

`.gitignore` 패턴에는 **`/` 를 붙인다** (`/coverage.out`, 아니면 어느 깊이에서든 잡힌다).

---

## 7. 현재 상태 · 다음 할 일

```
규칙 21종 · 테스트 358개 · 퍼징 5,600만 케이스 무결
원본 97개 항목 이식 완료 (이식 18 · 조합 재료 3 · 버림 76)
정상 코퍼스 12쪽: 458건 → 26건 (오탐 41 + 중복 391) · HIGH 0건
커버리지: main 98.5% (run 100%) · scanner 99.0% · tokenizer 95.1%
```

**26·27교시** — eTLD+1 · 호스트별 집계 · 정상 코퍼스 12쪽 · `corpus_test.go`.
**28교시** — `run(args, stdout, stderr)` 로 CLI 테스트 가능화 · `main_test.go` · `severity_test.go`(상수 순서 단언).
**29교시** — 코퍼스에 공격 19종 주입 측정(456건 미탐 0) · 중첩 폼 HIGH 오탐 수정(`FormAccepted`).
주입 측정 코드는 스크래치패드에만 있다 — 영구 테스트화는 아래 2번.

### 다음 (우선순위 순)

1. **`formaction` 미탐** — `<button formaction="http://IP/">` 로 보내면
   `form-action-ip` · `exfil-channel` · `cross-origin-password-form` 이 전부 0건 (실측).
2. **주입 측정을 영구 테스트로** — 정상 코퍼스 × 공격 조각 × 위치(body 시작·끝, 주석·textarea 대조군).
   발견 오프셋이 주입 구간 안에 있는지로 판정한다.
3. `<input form="id">` 원격 연결 — 스택으로는 불가, 트리 + id 인덱스 필요
4. 전체 트리 구성 — foster parenting, 삽입 모드 23개
5. punycode 호스트 — 정상 IDN과 구별하려면 혼합 스크립트 판정 필요
6. eTLD+1 접미사 표 확장 — 24개만 내장. 표에 없으면 마지막 두 라벨로 떨어져 **미탐 방향**

### 문서 갱신 규칙

규칙을 추가하면 **README(규칙 표) · DISCUSSION.md · Artifact 셋 다** 갱신한다.
문서가 뒤처지면 사용자가 지적하기 전에 먼저 알린다.
**틀린 숫자를 기록에 남기지 않는다** — 정정할 때는 정정 사실도 함께 남긴다
(예: DISCUSSION.md 9절의 "탐지 항목 9개 → 97개" 정정).
