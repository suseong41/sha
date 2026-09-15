# suseong-html-analyzer

![CI](https://github.com/suseong41/suseong-html-analyzer/actions/workflows/ci.yml/badge.svg)

HTML을 파싱해 **XSS·피싱·리소스 위험**을 찾아내는 정적 보안 스캐너 (Go).
외부 의존성 없이 표준 라이브러리만으로 동작한다.

정적 분석 도구다. "패턴이 존재한다"는 것을 보고할 뿐,
공격자가 그 값을 실제로 제어하는지까지는 증명하지 않는다.

---

### 기능

WHATWG 토크나이저(브라우저와 동일하게 해석)를 만들고, 그 위에 규칙을 얹는다.

* **파싱** — `<script>`/`<style>` 원시 텍스트, 문자 참조 디코딩, 주석·DOCTYPE,
  script escaped state, 열린 요소 스택까지 브라우저와 동일하게 처리
* **구조 질의** — 열린 요소 스택으로 "지금 어느 `<form>` 안인가"를 브라우저와 같게 판정하고,
  `form="id"` 로 멀리 떨어진 폼에 붙은 요소(form owner)까지 따라간다
* **출처 판정** — 등록 가능한 도메인(eTLD+1) 기준.
  `static.example.com` 은 `www.example.com` 페이지에서 외부가 아니다
* **집계** — 같은 원인은 한 줄로 묶는다.
  CDN 한 곳에서 스크립트 30개를 불러도 조치는 하나이므로 `(30곳)` 으로 보고한다
* **탐지 규칙 23종** (심각도 · 분류별)

  | 심각도 | 분류 | 규칙 | 내용 |
  |---|---|---|---|
  | HIGH | exfiltration | `cleartext-credentials` | 비밀번호가 평문(http)으로 전송 |
  | HIGH | exfiltration | `cross-origin-password-form` | 비밀번호 폼이 외부 도메인으로 전송 |
  | HIGH | exfiltration | `form-action-ip` | 폼이 IP 주소로 직접 전송 |
  | HIGH | exfiltration | `exfil-channel` | 스크립트·폼이 외부 메시징 API로 전송 |
  | HIGH | exfiltration | `phishing-interstitial` | CDN이 대상을 피싱으로 분류 (제3자 판정) |
  | HIGH | execution | `webshell-signature` | 스크립트 내 웹셸 시그니처 |
  | HIGH | execution | `meta-refresh-scheme` | `meta refresh` 가 `data:`/`javascript:` 로 이동 |
  | HIGH | execution | `data-uri-document` | 실행 가능한 `data:` URI 를 iframe/object/script 에 삽입 |
  | HIGH | origin | `base-href-external` | `<base href>` 가 외부 도메인 — 모든 상대 URL이 그쪽으로 |
  | HIGH | origin | `mixed-script-host` | 호스트 라벨에 모양이 같은 문자 체계가 섞임 (`аpple.com` 의 키릴 а) |
  | MEDIUM | execution | `javascript-url` | `javascript:` URL (문자 참조 우회 포함) |
  | MEDIUM | execution | `dangerous-download` | `.hta`·`.scr`·`.vbs` 등으로 연결되는 링크 |
  | MEDIUM | origin | `iframe-sandbox-escape` | `allow-scripts` 와 `allow-same-origin` 동시 허용 |
  | MEDIUM | supply-chain | `sri-missing` | 외부 리소스에 `integrity` 없음 |
  | MEDIUM | supply-chain | `mixed-content` | HTTPS 페이지의 `http://` 하위 리소스 |
  | MEDIUM | supply-chain | `resource-ip-literal` | 하위 리소스를 IP 주소에서 로드 |
  | MEDIUM | evasion | `obfuscated-eval` | `eval()` + 디코더(`atob` 등) 조합 |
  | MEDIUM | evasion | `noscript-breakout` | `<noscript>` 안 속성값·주석·`<style>` 에 숨긴 `</noscript>` 로 탈출 |
  | MEDIUM | hardening | `weak-password-field` | 이름은 비밀번호인데 `type` 이 `password` 가 아님 |
  | MEDIUM | hardening | `local-credential-post` | 비밀번호 폼이 `localhost`·`127.0.0.1` 로 전송 |
  | LOW | evasion | `zero-width` | 제로폭 문자 난독화 |
  | LOW | hardening | `inline-handler` | 인라인 이벤트 핸들러 (`onclick` 등) |
  | INFO | hardening | `target-blank-no-rel` | `target=_blank` 에 `rel=noopener` 없음 |



---

### 사용 방법

```sh
go build .

# 파일만 스캔
./suseong-html-analyzer page.html

# URL을 주면 출처 기반 규칙(외부 도메인 폼·혼합 콘텐츠·SRI)이 켜진다
./suseong-html-analyzer page.html https://example.com/

# 최소 심각도로 거르기 · 통계 함께 보기
./suseong-html-analyzer -min medium page.html https://example.com/
./suseong-html-analyzer -stats page.html

# 분류로 거르기
./suseong-html-analyzer -class exfiltration page.html https://example.com/
```

출력은 `파일:줄:칸: 심각도 분류 [규칙] 근거` 형식이라 에디터에서 바로 점프할 수 있다.

```
page.html:6:1:  HIGH   exfiltration [exfil-channel]  action=https://api.telegram.org/bot123/sendMessage
page.html:16:5: MEDIUM supply-chain [sri-missing]    c.example-cdn.com (3곳)
```
발견과 별개로 **분석의 한계**를 stderr 에 보고한다.
SPA 셸처럼 내용을 스크립트가 그리는 페이지가 그렇다.
이것은 위험이 아니라 **우리가 보지 못한 것**이므로 종료 코드에 영향을 주지 않는다.

**종료 코드** — `0` 발견 없음 · `1` 발견 있음 · `2` 사용법/입출력 오류.
CI에서 `-min high` 로 걸어 실패시킬 수 있다.

#### Docker 로 URL 검사

파일 대신 URL 을 주면 서버가 페이지를 가져와 스캔한다.

```sh
docker build -t sha .
docker run --rm -p 127.0.0.1:8080:8080 sha

# 다른 터미널에서
curl -s -H 'Content-Type: application/json' \
     -d '{"url":"https://www.naver.com/"}' \
     http://127.0.0.1:8080/api/scan
```

```json
{
  "url": "https://www.naver.com/",
  "findings": [
    { "line": 1,  "col": 1655, "severity": "MEDIUM", "class": "supply-chain", "code": "sri-missing",    "evidence": "ssl.pstatic.net (4곳)" },
    { "line": 24, "col": 1939, "severity": "LOW",    "class": "hardening",    "code": "inline-handler", "evidence": "<button onclick=…>" }
  ],
  "notes": []
}
```

(일부 필드와 발견을 줄였다.) 발견은 심각도 순으로 정렬되어 온다.
내부망·사설 IP·루프백 주소는 가져오지 않는다 — `192.168.0.1` 같은 주소를 넣으면 `502` 가 돌아온다.
다른 서비스에 붙이는 방법은 [docs/INTEGRATION.md](docs/INTEGRATION.md) 에 있다.

---

### 빌드 · 테스트

* Go 1.27 이상, 외부 의존성 없음

```sh
go test ./...          # 단위 테스트 + 퍼즈 씨앗
go vet ./...

# 퍼징 (파서·규칙의 크래시/무한루프 탐색)
go test ./tokenizer -run '^$' -fuzz FuzzTokenizer -fuzztime 1m
```

#### 실전 측정

```sh
./tools/measure.sh      # tools/sites.txt 의 사이트를 받아 전수 스캔하고 집계
./tools/measure.sh -f   # 모두 다시 받는다
```

받은 페이지는 `testdata/live/` 에 두고 **커밋하지 않는다**.
코퍼스가 *변하지 않는 회귀 기준*이라면, 이쪽은 *그날의 웹*을 보는 도구다.

#### 회귀 코퍼스

`testdata/corpus/` 에 실제 웹에서 받은 **정상 페이지 21쪽**이 있다(한국어·영어·일본어·키릴·아랍·데바나가리).
`scanner/corpus_test.go` 가 두 방향으로 단언한다.

| | 정상 21쪽 | `malicious_sample.html` |
|---|---|---|
| 잡는 것 | **오탐** — 정상인데 HIGH | **미탐** — 악성인데 조용함 |
| 단언 | `HIGH == 0` | `HIGH >= 3` |

한쪽만으로는 속일 수 있다. 오탐 단언만 있으면 *아무것도 찾지 않는 스캐너*가,
미탐 단언만 있으면 *전부 HIGH 로 찍는 스캐너*가 만점을 받는다.

```sh
go test ./scanner -run Corpus -v      # 페이지마다 서브테스트로 갈라진다
```