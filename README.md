# SHA — Suseong-Html-Analyzer

![CI](https://github.com/suseong41/sha/actions/workflows/ci.yml/badge.svg)
[![Docker Hub](https://img.shields.io/docker/v/suseong41/sha?label=docker%20hub&sort=semver)](https://hub.docker.com/r/suseong41/sha)

**SHA**(Suseong-Html-Analyzer)는 HTML을 파싱해 **XSS·피싱·리소스 위험**을 찾아내는 정적 보안 스캐너다 (Go).
외부 의존성 없이 표준 라이브러리만으로 동작한다. 아래에서는 **SHA** 로 부른다.

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
* **탐지 규칙 25종** (심각도 · 분류별)

  | 심각도 | 분류 | 규칙 | 내용 |
  |---|---|---|---|
  | HIGH | exfiltration | `cross-origin-password-form` | 비밀번호 폼이 외부 도메인으로 전송 |
  | HIGH | exfiltration | `form-action-ip` | 폼이 IP 주소로 직접 전송 |
  | HIGH | exfiltration | `exfil-channel` | 스크립트·폼이 외부 메시징 API로 전송 |
  | HIGH | exfiltration | `phishing-interstitial` | CDN이 대상을 피싱으로 분류 (제3자 판정) |
  | HIGH | execution | `webshell-signature` | 웹셸 관리 화면 — 알려진 웹셸 이름 + 파일 업로드 칸, 또는 이름 없이 PHP 안전 모드 상태 + 디렉터리 권한(`drwx`) + 파일 업로드 칸 |
  | HIGH | execution | `local-system-object` | 스크립트가 방문자 PC 의 파일·프로세스를 다루는 Windows 객체를 만듦 (드로퍼·다운로더) |
  | HIGH | execution | `encoded-shellcode` | 스크립트가 `%uXXXX` 로 숨긴 이진 코드(셸코드) — 풀면 글자가 아닌 값이 나옴 |
  | HIGH | execution | `meta-refresh-scheme` | `meta refresh` 가 `data:`/`javascript:` 로 이동 |
  | HIGH | execution | `data-uri-document` | 실행 가능한 `data:` URI 를 iframe/object/script 에 삽입 |
  | HIGH | origin | `base-href-external` | `<base href>` 가 외부 도메인 — 모든 상대 URL이 그쪽으로 |
  | HIGH | origin | `mixed-script-host` | 호스트 라벨에 모양이 같은 문자 체계가 섞임 (`аpple.com` 의 키릴 а) |
  | MEDIUM | exfiltration | `cleartext-credentials` | 비밀번호가 평문(http)으로 전송 — 대개 피해 사이트의 설정 실수 |
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

  스크립트를 읽는 규칙(`exfil-channel` · `obfuscated-eval` · `local-system-object` · `encoded-shellcode`)은 **실행되는 코드 블록만** 본다.
  `<script type="application/json">` 같은 데이터 블록은 실행되지 않는다 — GitHub 코드 화면이 파일 내용을 거기 담는다.

* **HIGH 규칙의 실측 근거** — 악성 HTML 24,636개로 재면 HIGH 11종 중 **5종**이 실제 표본에서 확인된다.

  | 확인됨 | 표본 | 아직 합성·주입 테스트뿐 | 왜 |
  |---|---:|---|---|
  | `local-system-object` | 3,741 | `cross-origin-password-form` · `base-href-external` | 표본에 페이지 URL 이 없어 출처 규칙이 설계대로 물러난다 |
  | `encoded-shellcode` | 154 | `mixed-script-host` | 표본에서 비ASCII 가 빠졌다 |
  | `webshell-signature` | 59 | `exfil-channel` · `phishing-interstitial` · `meta-refresh-scheme` | 악성코드 표본이라 피싱 수법이 없다 — 0건 |
  | `form-action-ip` | 9 | | |
  | `data-uri-document` | 3 | | |

  합성 양성은 **규칙이 살아 있다**는 증거이지 그 공격을 실제로 만난다는 증거가 아니다.
  규칙별 근거와 "무엇이 있어야 잴 수 있나"는 [DISCUSSION.md](DISCUSSION.md) §12.46 에 있다.



---

### 사용 방법

빌드하면 실행 파일 이름은 `sha` 다. 예전 이름으로 받아 두신 것이 있다면 [이름이 바뀌었다](#이름이-바뀌었다) 를 보라.

```sh
go build .

# 파일만 스캔
./sha page.html

# URL을 주면 출처 기반 규칙(외부 도메인 폼·혼합 콘텐츠·SRI)이 켜진다
./sha page.html https://example.com/

# 최소 심각도로 거르기 · 통계 함께 보기
./sha -min medium page.html https://example.com/
./sha -stats page.html

# 분류로 거르기
./sha -class exfiltration page.html https://example.com/

# 버전
./sha -version
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
SHA 이미지는 Docker Hub 에 있다 — `linux/amd64` · `linux/arm64`, 3.4MB(`scratch` 기반이라 셸도 패키지 관리자도 없다).

```sh
docker run --rm -p 127.0.0.1:8080:8080 suseong41/sha:0.2.0

# 직접 빌드하려면
docker build -t sha . && docker run --rm -p 127.0.0.1:8080:8080 sha

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

동시에 처리하는 스캔은 **기본 4개**다(`-max-scans`). 자리가 없으면 2초까지 기다렸다가 `503` 과 `Retry-After: 1` 을 돌려준다.
5MB 페이지 하나가 약 50MB 를 쓰기 때문에 정한 값이다 — 메모리 256MB 로 제한한 컨테이너는 동시 10개에서 죽는다(측정: DISCUSSION §12.49).

서버가 살아 있는지는 `GET /healthz` 로 묻는다 — `{"status":"ok"}` 만 돌려주고, 밖으로 나가지 않으며 로그도 남기지 않는다.
도는 버전은 시작 로그와 이미지 라벨에 있다(`/webscan -version` 은 없다 — 서버는 `-addr` 만 받는다).

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

`testdata/` 에 실제 웹에서 받은 **정상 페이지 21쪽**이 있다(`corpus/` 20쪽 + `jnu_main.html`, 한국어·영어·일본어·키릴·아랍·데바나가리).
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

---

### 이름이 바뀌었다

2026-09-21 에 식별자를 `suseong-html-analyzer` 에서 **`sha`** 로 바꿨다. 부르는 이름은 **SHA**(Suseong-Html-Analyzer)다.

| | 옛 이름 | 지금 |
|---|---|---|
| 저장소 · 모듈 | `github.com/suseong41/suseong-html-analyzer` | `github.com/suseong41/sha` |
| 이미지 | `suseong41/suseong-html-analyzer` | `suseong41/sha` |
| 실행 파일 | `suseong-html-analyzer` | `sha` |

전부 소문자다 — Docker 가 대문자 이미지 이름을 받지 않기 때문에, 한 곳이 소문자여야 한다면 **전부** 소문자인 편이 어긋남이 없다.
대문자 `SHA` 는 사람이 읽는 자리에만 쓴다.

옛 이미지 `suseong41/suseong-html-analyzer:0.1.0` 은 **지우지 않는다** — 이미 받아 쓰는 사람이 깨진다.
새 이름의 첫 판은 `suseong41/sha:0.2.0` 이고, GitHub 은 옛 저장소 주소를 새 주소로 리다이렉트해 준다.

---

### 라이선스

MIT — [LICENSE](LICENSE). 마음대로 쓰고 고치고 배포해도 된다. 저작권 고지만 남겨 달라.

`old_c_files/ExternalLib/gTest/` 만 예외다 — Google 의 GoogleTest(BSD 3-Clause)이고,
Go 로 옮기기 전 C++ 원본을 시험하던 코드라 빌드에도 이미지에도 들어가지 않는다. [NOTICE](NOTICE) 참고.
