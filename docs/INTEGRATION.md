# SHA 연동 명세 — my_homepage

이 문서는 SHA(sha)를 `my_homepage` 에 붙이는 작업자를 위한 명세다.
여기 적힌 설정과 코드는 전부 my_homepage 와 같은 구성(nginx + api + sha)을 compose 로 띄워 실제로 돌려봤다.
돌려본 방법과 **돌려보지 못한 것**은 [7. 검증 기록](#7-검증-기록)에 있다. 확인되지 않은 부분은 본문에도 그렇다고 표시했다.

작성 2026-09-16 · 갱신 2026-09-22(진행 상황 흘려받기, SHA 0.3.0) · 2026-09-21(이미지 받아 쓰기 · `GET /healthz` · 동시 스캔 상한) · SHA 는 Go 1.27 · 이미지 `scratch` 기반

---

## 0. 구성

```
브라우저 ─443─▶ (Cloudflare) ─▶ nginx ─┬─ /             정적 html/
                                        ├─ /api/…        ▶ api:8000   FastAPI (기존)
                                        └─ /api/scan     ▶ sha:8080   SHA (추가)
```

- SHA 는 **JSON 을 돌려주는 API 하나**다. 페이지는 my_homepage 가 그린다.
- SHA 는 compose 네트워크 안에서만 닿는다. 호스트나 인터넷에 포트를 열지 않는다.
- SHA 는 사용자가 넣은 URL 을 **서버에서 직접 가져온다.** 내부망·메타데이터·사설 주소로 가는 요청은 SHA 가 막는다(SSRF 방어). 이 방어는 SHA 안에 있으므로 my_homepage 쪽에서 따로 할 일은 없다.

---

## 1. API 계약

### 요청

```
POST /api/scan
Content-Type: application/json

{"url": "https://example.com/"}          가져와서 검사한다
{"html": "<!DOCTYPE html>…", "url": "…"}  받은 것을 검사한다 (가져오지 않는다)
```

**입력이 둘로 갈린다.** `html` 이 있으면 **밖으로 나가지 않는다** — `url` 은 가져올 곳이 아니라 **출처로 삼을 주소**가 된다(CLI 의 `sha 파일.html <주소>` 와 같다).

| | `url` 만 | `html` 이 있을 때 |
|---|---|---|
| 가져오기 | 한다 | **안 한다** |
| `url` 의 뜻 | 가져올 곳 | 출처로 삼을 주소 (없어도 된다) |
| 응답의 `url` | 리다이렉트를 따라간 **최종 주소** | **보낸 값 그대로** |
| 흘려받을 때 단계 | `fetch` → `scan` | **`scan` 하나뿐** |
| 502 | 날 수 있다 | 날 수 없다 |

`url` 을 주지 않으면 출처 기반 규칙(`cross-origin-password-form` 등)은 설계대로 물러난다 — 모르는 것을 단정하지 않는다.

| 조건 | 어기면 |
|---|---|
| `Content-Type` 이 `application/json` | 415 |
| 본문 4KB 이하 (`html` 도 이 안에 들어와야 한다) | 413 (nginx 에서 먼저 막힌다 — 아래 오류 표) |
| `url` 과 `html` 중 **하나는 있어야** 한다 | 400 |
| `url` 이 2048자 이하 | 400 |
| `http` 또는 `https` | 502 |

폼 형식(`application/x-www-form-urlencoded`)은 받지 않는다. 폼 형식은 다른 사이트의 `<form>` 이 방문자 브라우저를 시켜 몰래 보낼 수 있기 때문이다.

### 성공 응답 — 200

```json
{
  "url": "https://example.com/",
  "findings": [
    {
      "line": 24, "col": 1939,
      "severity": "HIGH", "class": "exfiltration",
      "code": "cross-origin-password-form",
      "title": "비밀번호 폼이 외부 도메인으로 전송됨",
      "evidence": "bank.example.com → evil.example  (action=https://evil.example/steal)"
    }
  ],
  "notes": [],
  "rules": {
    "cross-origin-password-form": {
      "why": "비밀번호를 받는 폼이 이 페이지와 다른 도메인으로 전송합니다. …",
      "fix": "action 이 가리키는 도메인을 확인합니다. …"
    }
  }
}
```

| 필드 | 설명 |
|---|---|
| `url` | 리다이렉트를 따라간 **최종** URL. 사용자가 입력한 URL 과 다를 수 있다. **`html` 을 보냈으면 보낸 `url` 그대로**(가져오지 않았다) |
| `rules` | 이번 결과에 **나온 규칙의 설명만**. 발견마다가 아니라 **코드마다 한 번** — 같은 규칙이 70번 나와도 설명은 하나다. 실측으로 한 페이지에 나오는 코드는 최대 5종이라 1.2KB 안쪽이다 |
| `findings` | **서버가 이미 정렬했다** — 심각도 내림차순(`HIGH` → `MEDIUM` → `LOW` → `INFO`). 클라이언트에서 다시 정렬하지 않는다 |
| `findings[].evidence` | 대상 페이지의 **원본 문자열**. `<img onerror=…>` 같은 마크업이 이스케이프되지 않은 채로 온다 → [2절](#2-결과를-그리는-쪽--반드시-지킬-것) |
| `notes` | "스캐너가 이 페이지를 다 보지 못했다"는 참고. 예: 내용을 스크립트가 그리는 SPA, WAF 차단 페이지 |
| 빈 결과 | `findings` 와 `notes` 는 비어 있어도 `null` 이 아니라 **`[]`**, `rules` 는 **`{}`** 다 |

**`rules` 는 없을 수도 있다고 보고 그려라.** 정적 파일과 이미지는 따로 배포되므로, 페이지가 먼저 올라가면 옛 서버가 이 필드 없이 응답한다. `data.rules?.[code]` 처럼 없을 때를 다뤄 설명만 빠지고 표는 그대로 나오게 한다.

### 오류 응답

**오류 본문이 JSON 이라는 보장은 없다.** 누가 응답했느냐에 따라 형식이 다르다.

| 상태 | 응답한 곳 | 본문 형식 | 뜻 |
|---|---|---|---|
| 400 | SHA | JSON `{"error": "…"}` | JSON 이 아니거나 `url` 이 비었거나 너무 김 |
| 413 | **nginx** | **HTML** | 본문이 4KB 초과 |
| 415 | SHA | JSON | `Content-Type` 이 JSON 이 아님 |
| 429 | **nginx** | **HTML** | 요청이 너무 잦음 |
| 502 | SHA | JSON | 가져오지 못함 — 내부 주소·차단된 주소·연결 실패·시간 초과·5MB 초과 **전부 같은 메시지** |
| 503 | SHA | JSON | 처리 중인 요청이 상한(기본 4)에 닿았고 2초를 기다려도 자리가 안 남. `Retry-After: 1` 이 함께 온다 |
| 404 · 405 | SHA | **text/plain** | 경로나 메서드가 틀림 |

502 의 원인을 일부러 구별해 주지 않는다. `intranet(10.1.2.3) 로는 접속하지 않는다` 같은 상세를 돌려주면, 우리 서버가 **내부 DNS 를 대신 조회해 주는 창구**가 된다. 원인은 응답 대신 **SHA 의 서버 로그**에 종류로 남는다(6절).

### 진행 상황을 흘려받기 — `Accept: application/x-ndjson`

같은 경로에 `Accept` 헤더 하나만 더하면 **끝난 결과 대신 진행 상황이 줄 단위로** 온다. 헤더가 없으면 위와 똑같이 한 덩어리 JSON 이다 — **기존 연동은 아무것도 바꿀 필요가 없다.**

```
POST /api/scan
Content-Type: application/json
Accept: application/x-ndjson
```

```jsonl
{"t":"start","url":"https://naver.com/"}
{"t":"begin","name":"fetch"}
{"t":"end","name":"fetch","ms":125,"text":"263,350 바이트","final":"https://www.naver.com/"}
{"t":"begin","name":"scan"}
{"t":"end","name":"scan","ms":10,"text":"토큰 9,497개 · 발견 3건"}
{"t":"done","ms":136,"result":{ …위의 200 응답과 같은 것… }}
```

| 줄 | 뜻 |
|---|---|
| `start` | 요청을 받았다 |
| `begin` / `end` | 단계의 시작과 끝. 단계는 **둘뿐**이다 — `fetch`(가져오기) · `scan`(파싱·규칙). **`html` 을 보냈으면 `fetch` 는 아예 오지 않는다** |
| `end.ms` | 그 단계에 걸린 밀리초. 단계 합은 `done.ms` 를 넘지 않는다 |
| `done.result` | **평소 200 응답과 완전히 같은 객체.** 화면은 이것으로 결과를 그리면 된다 |
| `error` | 실패. 이 줄이 오면 `done` 은 오지 않는다 |

**`ms` 는 0이면 아예 오지 않는다.** `html` 입력은 가져오기가 없어 전체가 0ms 로 끝나는 일이 흔하다 — 받는 쪽은 없는 경우를 다뤄야 한다(`ev.ms ?? 0`). 실제로 이 자리에서 화면에 `undefined ms` 가 찍히는 것을 발견했다.

**중요 — 흘리기 시작하면 상태 코드를 바꿀 수 없다.** 첫 줄을 보내는 순간 `200 OK` 가 확정되므로, 그 뒤의 실패(가져오기 실패 등)는 **HTTP 상태가 아니라 `error` 줄**로 온다. 받는 쪽은 `done` 이 오지 않고 끝나는 경우도 실패로 다뤄야 한다.

반면 **흘리기 전에 나는 거절**(415 · 400 · 503 · nginx 의 413 · 429)은 지금처럼 상태 코드와 JSON 으로 온다.

### 상태 확인 — `GET /healthz`

```
GET /healthz   →   200  {"status":"ok"}
```

`GET`(과 `HEAD`)만 받고 나머지 메서드는 405 다. 이 경로는 **밖으로 나가지 않고 로그도 남기지 않는다.** 버전은 일부러 담지 않는다 — 인증 없는 경로에서 무엇이 도는지 알려 줄 이유가 없다. 도는 버전은 시작 로그(`{"msg":"listening","version":"0.1.0"}`)와 이미지 라벨에 있다. 쓰는 곳은 6절에.

---

## 2. 결과를 그리는 쪽 — 반드시 지킬 것

**이 절이 이 문서에서 가장 중요하다.** 스캔 결과는 **아무 방문자가 고른 아무 웹페이지**에서 나온 문자열이다. 그대로 HTML 로 넣으면 suseong.org 에서 공격자의 스크립트가 실행된다.

### 규칙

1. **응답의 모든 문자열은 공격자가 고른 값으로 취급한다.** `evidence` 만이 아니라 `title`, `url`, `notes`, `code` 도 마찬가지다.
2. **`innerHTML` · `outerHTML` · `insertAdjacentHTML` · `document.write` 에 넣지 않는다.** `textContent` 와 `createElement` 로 넣는다.
   템플릿 리터럴(`` `${…}` ``) 자체가 문제가 아니라, **그 결과를 HTML 로 해석되는 곳에 넣는 것**이 문제다.
3. **서버는 `evidence` 를 이스케이프해서 보내지 않는다.** 이스케이프는 값을 넣는 자리(HTML 본문·속성·URL·스크립트)마다 방법이 달라서 서버가 미리 할 수 없다. 받은 쪽에서 직접 이스케이프한 뒤 `innerHTML` 에 넣는 방식도 쓰지 않는다. `textContent` 를 쓰면 브라우저가 자리에 맞게 처리한다.
4. **`url` 을 클릭할 수 있는 링크로 만들지 않는다.** 이 페이지는 악성일 수 있는 사이트에 대한 보고서다.
5. **`notes` 가 비어 있지 않으면 "발견 없음"을 "안전함"으로 보여주지 않는다.** 스캐너가 페이지 내용을 다 보지 못했다는 뜻이다.
6. **오류 응답을 JSON 이라고 가정하지 않는다** — `Content-Type` 을 먼저 확인한다(1절 오류 표).
7. **스캔 결과를 `marked` 같은 Markdown 렌더러에 넣지 않는다.** Markdown 은 HTML 을 통과시킨다.

### 대조 — 지금의 카드 함수 방식으로 그리면

```js
// 하면 안 되는 방식 — 현재 index.html 의 repoCardHtml · postCardHtml 과 같은 모양
container.innerHTML = `<table><tr><td>${f.evidence}</td></tr></table>`;
```

`evidence` 가 `<img src=x onerror=alert(1)>` 이면 **실제 `<img>` 요소가 만들어지고 `onerror` 속성이 붙는다.** 브라우저에서는 그 자리에서 실행된다.

### 예시 — 결과 그리기

```js
// 공격자가 고른 문자열은 전부 textContent 로만 넣는다.
function renderScan(container, data) {
  container.replaceChildren();

  const target = document.createElement('p');
  target.textContent = `대상: ${data.url}`; // 링크로 만들지 않는다
  container.append(target);

  if (data.notes.length > 0) {
    const ul = document.createElement('ul');
    for (const note of data.notes) {
      const li = document.createElement('li');
      li.textContent = note;
      ul.append(li);
    }
    container.append(ul);
  }

  if (data.findings.length === 0) {
    const p = document.createElement('p');
    p.textContent = data.notes.length > 0
      ? '발견 없음 — 단, 위 참고 사항 때문에 이 결과가 페이지 전체를 대표하지 않습니다.'
      : '발견 없음';
    container.append(p);
    return;
  }

  const table = document.createElement('table');
  for (const f of data.findings) {
    const row = table.insertRow();
    for (const value of [`${f.line}:${f.col}`, f.severity, f.class, f.code, f.title, f.evidence]) {
      row.insertCell().textContent = value;
    }
  }
  container.append(table);
}
```

### 예시 — 호출

```js
// base 는 테스트용 — 페이지에서는 '' (같은 출처).
export async function scanUrl(url, base = '') {
  let res;
  try {
    res = await fetch(`${base}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
  } catch {
    return { ok: false, message: '서버에 연결하지 못했습니다.' };
  }
  // 오류 응답은 JSON 이 아닐 수 있다 — nginx 413·429 는 HTML, 없는 경로·메서드는 text/plain.
  const isJSON = (res.headers.get('Content-Type') || '').startsWith('application/json');
  const body = isJSON ? await res.json() : null;
  if (res.ok && body) return { ok: true, data: body };
  const byStatus = { 413: '요청이 너무 큽니다.', 429: '요청이 너무 잦습니다. 잠시 후 다시 시도하세요.' };
  return { ok: false, status: res.status, message: body?.error ?? byStatus[res.status] ?? `요청이 실패했습니다 (${res.status}).` };
}
```

`message` 도 화면에 넣을 때는 `textContent` 로 넣는다.

`export` 는 모듈 파일로 쓸 때만 필요하다. `<script>` 안에 바로 쓰면 지운다.

### 현재 index.html 에서 함께 볼 곳

SHA 연동과 직접 관계는 없지만, 같은 원리로 문제가 되는 곳이다.

| 위치 | 내용 |
|---|---|
| `repoCardHtml` · `postCardHtml` | API 데이터를 템플릿 리터럴로 `innerHTML` 에 넣는다. 지금은 본인의 GitHub·티스토리 데이터라 위험이 낮다 |
| `onclick="openReadme('${repo.name}', …)"` | 속성 안의 JavaScript 문자열에 데이터를 넣는다. 저장소 이름에 `'` 가 들어가면 스크립트 문맥이 깨진다 |
| `modalBody.innerHTML = marked.parse(data.content)` | `marked` 는 기본으로 HTML 을 소독하지 않는다 |
| `<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js">` (563행) | **SHA 로 이 파일을 스캔한 결과:** `MEDIUM supply-chain [sri-missing]`. 버전이 고정되어 있지 않아 `integrity` 도 붙일 수 없다 — 버전을 고정하고 `integrity` 를 붙이거나, 파일을 직접 호스팅한다 |

---

## 3. compose — sha 서비스

`docker-compose.yml` 의 `services:` 아래에 추가한다. **저장소를 복사해 빌드할 필요가 없다** — Docker Hub 의 이미지를 받아 쓴다.

```yaml
  sha:
    image: suseong41/sha:0.2.0
    expose:
      - "8080"
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    mem_limit: 256m
    pids_limit: 64
    restart: unless-stopped
```

nginx 의 `depends_on` 에 `sha` 를 추가한다.

| 줄 | 이유 |
|---|---|
| `expose` (**`ports` 가 아니다**) | 같은 compose 네트워크의 nginx 만 닿는다. `ports` 는 호스트에 연다 |
| `read_only` | SHA 는 디스크에 쓰지 않는다. 컨테이너 안에서 파일을 만들 수 없게 한다 |
| `cap_drop: ALL` · `no-new-privileges` | 커널 권한을 전부 뺀다. SHA 이미지는 이미 비루트(UID 65532)로 돈다 |
| `image` 에 **버전을 고정** | `latest` 로 두면 재시작할 때마다 다른 것이 돌 수 있다. 올릴 때는 이 줄을 고치고 `docker compose pull sha && docker compose up -d sha` |
| `mem_limit` · `pids_limit` | **2026-09-21 에 실제로 재서 고른 값이다**(SHA 0.2.0). 5MB 페이지 하나가 약 50MB 를 쓴다 — `mem_limit: 256m` 에서 동시 9 까지는 살지만 **10 부터 컨테이너가 OOM 으로 죽고 그 순간의 요청이 전부 실패**한다. SHA 는 동시 스캔을 **기본 4개**로 제한하므로(넘치면 2초 기다렸다 503) 이 한도 안에 머문다 — 동시 256 요청을 부어도 메모리 112MB, OOM 없음. 상한을 올리려면 `-max-scans` 와 `mem_limit` 을 **함께** 올린다: 대략 `mem_limit ≈ max-scans × 50MB + 60MB` |

이미지는 컨테이너 안에서 `0.0.0.0:8080` 으로 듣도록 만들어져 있다. 따로 설정할 필요 없다. 이 값을 `127.0.0.1` 로 바꾸면 로그에는 정상으로 뜬 것처럼 찍히지만 nginx 가 닿지 못한다.

---

## 4. nginx

기존 `nginx/nginx.conf` 전체를 아래로 바꾼 모습이다. 기존과 달라진 곳은 `limit_req_zone`, Cloudflare `real_ip` 블록, `add_header` 셋, `location = /api/scan` 이다.

```nginx
# 요청 속도 제한 — /api/scan 한 곳에만 건다. 키는 방문자 IP(아래 real_ip 로 복원한 값).
limit_req_zone $binary_remote_addr zone=scan:10m rate=6r/m;

server
{
    listen 80;
    server_name suseong.org www.suseong.org;
    return 301 https://$host$request_uri;
}

server
{
    listen 443 ssl;
    server_name suseong.org www.suseong.org;

    ssl_certificate /etc/nginx/certs/suseong.org.crt;
    ssl_certificate_key /etc/nginx/certs/suseong.org.key;

    root /usr/share/nginx/html;
    index index.html;

    # Cloudflare 뒤: 방문자 IP 는 CF-Connecting-IP 에 있다. Cloudflare 대역에서 온 연결의 헤더만 믿는다.
    # 대역 목록은 https://www.cloudflare.com/ips/ 에서 주기적으로 갱신한다.
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 131.0.72.0/22;
    set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;
    set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;
    set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2a06:98c0::/29;
    set_real_ip_from 2c0f:f248::/32;
    real_ip_header CF-Connecting-IP;

    # always — 없으면 4xx·5xx 응답에는 헤더가 안 붙는다.
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" always;

    # 정확 일치(=)는 아래 /api/ 접두사보다 먼저 고른다.
    location = /api/scan
    {
        client_max_body_size 4k;
        limit_req zone=scan burst=3 nodelay;
        limit_req_status 429;
        proxy_pass http://sha:8080;
        proxy_read_timeout 35s;

        # 진행 상황을 줄 단위로 흘려보내므로 모았다 보내면 안 된다.
        proxy_buffering off;
        proxy_http_version 1.1;
    }

    location /api/
    {
        proxy_pass http://api:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /
    {
        try_files $uri $uri/ =404;
    }
}
```

### 줄마다 짚을 것

**`limit_req_zone … rate=6r/m` · `burst=3 nodelay`** — 한 방문자가 연달아 4번까지 보낼 수 있고, 그 뒤로는 10초에 1번꼴이다. **시작값이다.** 실제 사용량을 보고 조정한다. `limit_req_zone` 은 `http` 문맥에 있어야 하는데, `conf.d/default.conf` 는 `http` 블록 안에 포함되므로 파일 맨 위에 둬도 된다.

**`real_ip` 블록** — Cloudflare 프록시를 켜 두면 nginx 가 보는 접속 IP(`$remote_addr`)는 방문자가 아니라 Cloudflare 서버다. 이 블록이 없으면 속도 제한이 **Cloudflare 서버 단위로** 걸린다. 한 사람이 남용해도 다른 방문자까지 막히거나, 제한이 사실상 걸리지 않는다. `set_real_ip_from` 은 **Cloudflare 대역에서 온 연결의 헤더만** 믿게 한다. 이게 없으면 원서버에 직접 붙은 누구나 `CF-Connecting-IP` 를 위조해 속도 제한을 피한다. 부수 효과로 기존 `/api/` 의 `X-Real-IP $remote_addr` 도 방문자 IP 가 된다.

- Cloudflare 대역은 2026-09-16 에 `https://www.cloudflare.com/ips-v4` · `ips-v6` 에서 받은 값이다. **바뀔 수 있으니 주기적으로 대조한다.**
- Cloudflare 프록시를 **끈** 상태로 운영한다면 이 블록을 지운다.

**`proxy_buffering off`** — 이게 없으면 nginx 가 응답을 **다 모았다가 한 번에** 보낸다. 서버는 줄마다 흘려보내는데 화면에는 똑같이 한 번에 도착하므로, **컨테이너에 직접 물어보면 멀쩡하고 nginx 뒤에서만 어긋난다**(실측으로 드러났다). `proxy_http_version 1.1` 은 업스트림과 청크 전송을 쓰기 위한 것이다. 이 두 줄은 `/api/scan` 에만 건다 — 다른 경로는 버퍼링이 이득이다.

**`location = /api/scan`** — `=` 정확 일치는 접두사 `/api/` 보다 먼저 선택된다. 순서와 무관하다. `client_max_body_size 4k` 가 SHA 의 본문 상한(4KB)과 같아서, 큰 요청은 SHA 까지 가지 않고 nginx 에서 413 으로 끝난다. `proxy_read_timeout 35s` 는 SHA 쪽 시간 상한(가져오기 10초, 응답 쓰기 30초)보다 길게 잡은 값이다.

**`add_header … always`** — `always` 가 있어야 404 같은 오류 응답에도 헤더가 붙는다. 그리고 **`location` 블록 안에 `add_header` 를 하나라도 쓰면, 그 블록에서는 `server` 수준의 `add_header` 가 전부 사라진다.** 헤더를 추가해야 하면 `server` 수준에서 추가한다. (두 문장 모두 nginx 문서의 동작이다. 이번 검증에서는 `always` 를 붙인 상태만 쟀다.)

**`/api/scan` 응답에는 CSP 헤더가 두 개 붙는다** — SHA 가 붙이는 `default-src 'none'` 과 nginx 가 붙이는 페이지용 정책이다. 브라우저는 둘 다 적용하므로 더 엄격한 쪽이 이긴다. 문제없다.

### CSP 를 켰다 (2026-09-22)

`Report-Only` 를 떼고 실제로 막는 정책으로 바꿨다. 켜기 전에 막히던 것을 전부 치웠고, **헤드리스 Chrome 으로 두 페이지를 열어 위반 0건**을 확인했다 — **로컬과 운영 둘 다**이지만, 운영은 처음에 1건이 났다(아래 「CDN 이 스크립트를 끼워 넣는다」).

| 막던 것 | 어떻게 치웠나 |
|---|---|
| 인라인 `<script>` 180줄 | `assets/main.js` 로 빼고 **DOM API 로 다시 씀**(`innerHTML` 이 README 모달 한 곳만 남았다) |
| `onclick="…"` 속성 | 목록에서 클릭을 한 번만 듣는 방식으로(`data-*` + `closest`) |
| 템플릿 안의 `style="…"` | `el.style.x = …` — **CSSOM 은 CSP 가 막지 않는다.** 덕분에 `style-src` 에서 `'unsafe-inline'` 을 뺐다 |
| CDN 의 `marked` | **직접 호스팅 + 버전 고정**(`marked 18.0.13`). `script-src 'self'` 가 되고 `sri-missing` 도 사라졌다 |

```
default-src 'self'; script-src 'self'; style-src 'self';
img-src 'self' data: https:; connect-src 'self';
object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

`img-src` 만 `https:` 로 넓다. README 의 배지가 여러 호스트에서 오는데 호스트 목록을 만들면 배지가 늘 때마다 조용히 깨지고, **이미지는 스크립트를 실행하지 않는다.**

> **버전을 안 적으면 최신을 쓰는 게 아니라 아무도 모르는 판을 쓰게 된다.** 고정하지 않은 `npm/marked/marked.min.js` 는 18.x 에서 그 파일이 사라지자 **jsdelivr 이 15.0.12 로 조용히 떨어뜨리고** 있었다.

#### 운영에서 한 가지 더 — CDN 이 스크립트를 끼워 넣는다

**로컬에서 위반 0건이어도 운영은 다를 수 있다.** 켠 첫날 운영에서만 1건이 났다 — Cloudflare 의 Web Analytics 자동 삽입이 `static.cloudflareinsights.com` 비컨을 `</body>` 앞에 붙이고 있었다. 원서버가 보낸 HTML 에는 없다.

- **맨 `curl` 로는 안 보인다.** `Accept: text/html` 이 붙은 **브라우저처럼 보이는 요청에만** 넣는다.
  확인: `curl -s -A 'Mozilla/5.0 Chrome/140' -H 'Accept: text/html' https://<도메인>/ | grep -c cloudflareinsights`
- **허용하려면 두 곳을 연다.** 받는 곳(`static.cloudflareinsights.com`)은 `script-src`, 보내는 곳(`cloudflareinsights.com/cdn-cgi/rum`)은 `connect-src` — 호스트가 달라서 한쪽만 열면 위반이 그대로 남는다.
- **택한 쪽**: 자동 삽입을 껐다(Cloudflare 대시보드 → Web Analytics → 해당 사이트 → 자동 설정 해제). 페이지가 스스로 부르지 않는 스크립트를 위해 정책을 넓히지 않는다.

같은 성질의 기능이 더 있다 — Rocket Loader · Email Address Obfuscation 도 **지나가는 HTML 을 고친다**(아직 재 보지 않았다). CSP 를 켤 때는 우리 파일만이 아니라 **앞단 설정도 함께 본다.**

---

## 5. Cloudflare 프록시 뒤에서 — 원서버 IP 가 드러난다

**코드나 설정으로 막을 수 없는 문제**라 따로 적는다. Cloudflare 프록시를 켜 두었다면 해당한다.

Cloudflare 를 앞에 두는 이유 중 하나는 **원서버 IP 를 숨기는 것**이다. 그런데 SHA 는 **누구나 입력한 URL 로 원서버에서 직접 요청을 보낸다.** 공격자가 자기 서버 주소를 넣고 접속 로그를 보면 원서버의 진짜 IP 가 찍혀 있다. 그 뒤로는 Cloudflare 를 거치지 않고 원서버에 직접 붙을 수 있다.

대응은 둘 중 하나, 또는 둘 다다.

| 대응 | 효과 |
|---|---|
| 원서버 방화벽에서 80/443 을 **Cloudflare 대역에서만** 받는다 | IP 가 알려져도 직접 붙지 못한다. 4절 `real_ip` 의 헤더 위조도 원천 차단된다 |
| SHA 의 나가는 요청만 **다른 IP(프록시·VPN)** 로 내보낸다 | 원서버 IP 가 애초에 드러나지 않는다 |

방화벽 규칙은 compose 밖(서버 운영체제나 클라우드 보안 그룹)의 일이다.

덤으로, 스캔 대상 사이트 중 Cloudflare 봇 차단을 쓰는 곳은 차단 페이지를 돌려준다. SHA 는 그걸 발견이 아니라 `notes` 로 알린다. 2절 규칙 5 가 필요한 이유 중 하나다.

---

## 6. 운영

**새 판이 나오면 올린다.** 두 가지가 이미지를 새로 만들 때만 갱신되기 때문이다.

- **CA 인증서** — 실행 이미지에 들어 있는 인증서 묶음. 오래 두면 폐기된 인증 기관을 계속 믿는다.
- **Go 보안 패치** — 이미지는 `golang:1.27-alpine` 에서 빌드되므로 새로 만들 때 최신 패치를 받는다.

`docker-compose.yml` 의 `image:` 줄에서 버전을 올린 뒤:

```bash
docker compose pull sha && docker compose up -d sha
```

어떤 판이 도는지는 시작 로그(`{"msg":"listening","version":"0.2.0"}`)와 이미지 라벨로 확인한다.

```bash
docker image inspect suseong41/sha:0.2.0 --format '{{index .Config.Labels "org.opencontainers.image.version"}}'
```

Go 버전 줄 자체(1.27)는 지원 기간이 끝나기 전에 SHA 저장소에서 올린다. SHA 저장소의 CI 가 푸시할 때와 매주 한 번 아래 검사를 돌리고, 알려진 취약점이 있으면 실패한다.

```bash
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

**SHA 는 요청마다 JSON 한 줄을 표준 출력에 남긴다** — `docker compose logs sha` 로 본다.

```json
{"time":"…","level":"INFO","msg":"scan","status":200,"scheme":"https","host":"example.com","final_host":"example.com","findings":0,"notes":0,"bytes":559,"ms":171}
{"time":"…","level":"WARN","msg":"scan","status":502,"reason":"blocked","scheme":"http","host":"192.168.0.1","ms":0}
{"time":"…","level":"INFO","msg":"scan rejected","status":415,"reason":"content_type"}
```

| 필드 | 뜻 |
|---|---|
| `reason` (502) | `blocked` 내부·예약 주소 · `dns` 이름 해석 실패 · `tls` 인증서 검증 실패 · `timeout` 시간 초과 · `too_large` 5MB 초과 · `other` 그 밖 |
| `reason` (거절) | `content_type` · `body`(본문이 JSON 이 아니거나 4KB 초과) · `input`(둘 다 없음) · `url_length` |
| `input` (200) | `url` 가져와서 검사 · `html` 받은 것을 검사. **`html` 이면 `host` 는 접속한 곳이 아니라 보낸 쪽이 적어 준 출처다** |
| `host` · `final_host` | 대상과 리다이렉트 뒤 최종 대상의 **호스트(포트 포함)만** |

**일부러 남기지 않는 것:** URL 의 경로·쿼리·조각·계정 정보, 요청 본문, 오류 문자열(사용자가 넣은 URL 이 통째로 들어 있다), 방문자 IP(SHA 는 nginx 의 IP 만 본다 — 방문자 IP 는 nginx 접속 로그에 있다). 사람들이 비밀번호 재설정 링크 같은 것을 넣어 볼 수 있기 때문이다. 이 로그를 다른 곳으로 보내더라도 필드를 더하지 않는다.

한 줄에 JSON 하나라서, 공격자가 고른 문자열에 줄바꿈이 섞여도 가짜 로그 줄이 생기지 않는다.

**상태 확인은 `GET /healthz` 다** (0.1.0 부터). 살아 있으면 `200` 과 `{"status":"ok"}` 만 돌려준다 — 버전도 호스트 이름도 넣지 않는다. 밖으로 나가지 않고 **로그도 남기지 않는다**(프로브가 초당 한 번씩 두드리면 로그가 그것뿐이 된다).

compose `healthcheck` 에는 여전히 넣지 못한다 — 실행 이미지에 셸도 `curl` 도 없어서 **컨테이너 안에서** 돌릴 명령이 없다. 대신 **밖에서 두드리는 것들**이 이 경로를 쓴다: 쿠버네티스 `httpGet` 프로브, 로드밸런서, nginx 업스트림 검사, 또는 호스트의 `curl`.

```bash
docker compose exec -T nginx wget -qO- http://sha:8080/healthz   # nginx 컨테이너에서
curl -s http://127.0.0.1:8080/healthz                            # 포트를 연 경우
```

`/healthz` 는 nginx 에 노출하지 않는다 — 4절 설정에는 `location = /api/scan` 만 있고, 나머지 `/api/` 는 기존 api 로 간다. 바깥에서 상태를 물을 이유가 없다.

---

## 7. 검증 기록

`my_homepage` 와 같은 구성을 스크래치 디렉터리에서 compose 로 띄워 확인했다. nginx 에는 테스트용 자체 서명 인증서를, api 자리에는 busybox 웹서버를 두었다. 외부로 나간 요청은 `example.com` 뿐이다.

**2026-09-21 재검증** — 이번에는 저장소를 빌드하지 않고 **배포된 이미지 `suseong41/sha:0.2.0` 을 받아** 같은 스택을 띄웠고, 이 문서 2절의 코드를 실제로 `my_homepage` 의 `index.html` 에 붙인 상태로 쟀다. 아래 표의 굵은 줄이 그날 것이다.

| 확인한 것 | 방법 | 결과 |
|---|---|---|
| 4절 nginx 설정 문법 | `nginx -t` (Cloudflare 대역 22개 포함 운영판 그대로) | 통과 |
| 3절 compose 문법 | `docker compose config` | 통과 |
| `/api/scan` → sha, `/api/posts` → api 라우팅 | nginx 경유 요청 | 각각 도착 |
| SHA 가 https 대상을 가져오는지 | `https://example.com/` 스캔 | 200 |
| sha 컨테이너 제약 | `docker inspect` | 읽기 전용 · `CapDrop=[ALL]` · `no-new-privileges` · 메모리 256MB · PID 64 · UID 65532 |
| sha 가 호스트에 열려 있지 않은지 | `docker compose port sha 8080` | 열린 포트 없음 |
| 보안 헤더가 200·404 에 붙는지 | 응답 헤더 확인 | 둘 다 붙음 |
| 본문 4KB 초과 | 8KB 본문 | nginx 가 413, 본문은 HTML |
| 오류 응답 형식 | GET `/api/scan` | 405, `text/plain` |
| 속도 제한이 방문자 단위인지 | 헤더를 믿는 설정, 같은 `CF-Connecting-IP` 8회 / 서로 다른 값 8회 | 4회 뒤 429 / 전부 통과 |
| 헤더 위조가 무시되는지 | 헤더를 믿지 않는 설정, 서로 다른 값 8회 | 4회 뒤 429 (위조 무시) |
| **배포 이미지로 같은 스택** | `image: suseong41/sha:0.2.0` 으로 compose up | **nginx·api·sha 정상, `/api/scan` 이 example.com 을 실제로 스캔** |
| **`/api/scan` · `/api/posts` · `/` 라우팅** | 자체 서명 인증서로 `https://suseong.org:8443` | **각각 sha · api · 정적 파일에 도달** |
| **보안 헤더(200·404)** | 응답 헤더 | **`nosniff` · `no-referrer` · CSP Report-Only 셋 다 붙음** |
| **헤더 위조 무시** | 운영 설정에서 서로 다른 `CF-Connecting-IP` 8회 | **4회 뒤 429 — 위조해도 키가 갈라지지 않는다** |
| **대조군(헤더를 믿는 설정)** | 서로 다른 IP 8회 / 같은 IP 8회 | **전부 통과 / 4회 뒤 429 — 방문자 단위 제한이 실제로 동작** |
| 2절 `renderScan` | jsdom — `evidence`·`title`·`url`·`notes`·`code` 에 마크업 주입 | 위험 요소 0개, 증거는 글자로 보임 |
| **2절 `renderScan` 재검증(2026-09-21)** | jsdom — 위 다섯에 더해 **`severity` 에도** 마크업 주입 | **위험 요소 0 · 이벤트 핸들러 0 · 위조된 등급은 `sev-info` 로 떨어짐** |
| 2절 대조군(`innerHTML`) | 같은 데이터 | `<img onerror>`·`<svg onload>` 요소가 만들어짐 |
| 2절 `scanUrl` | 띄운 스택에 실제 요청 (200 · 502 · 413 · 429 · 연결 실패) | 전부 기대한 결과 |
| **응답 6종 화면(2026-09-21)** | 200 발견 있음 · 200 참고만 · 502 · **503** · 429(HTML) · 연결 실패 | **문구가 종류마다 다르고, 어느 경우에도 버튼 잠김이 풀린다** |
| 현재 index.html | SHA CLI 로 스캔 | `sri-missing` 1건 (563행 marked) |
| 요청 로그 (6절) | 실제 이미지를 `--read-only --cap-drop ALL` 로 띄워 `docker logs` 확인. 토큰이 든 URL·내부 주소·폼 형식 요청 | JSON 한 줄씩, `reason` 기록, `SECRET` 0건 |
| SSRF — Docker 네트워크 안의 내부 서비스 | 같은 네트워크의 `api` 를 방어 켠/끈 이미지로 스캔 (SHA 저장소 53교시) | 켬 502 / 끔 200 |
| **CSP 를 브라우저가 실제로 강제하는지(2026-09-22)** | 헤드리스 Chrome 으로 `/` 와 `/tools/sha/` 를 연다 | **로컬 0건 · 운영 1건(CDN 삽입) → 원인 제거 후 운영도 0건** |
| **정책을 켠 채 페이지가 도는지** | 같은 실행의 DOM 덤프 | **저장소 카드 4 · 블로그 카드 3 · 사이드바 SHA 에 `.active`** = 스크립트가 돌았다 |
| **운영에서 실제로 Cloudflare 를 거친 응답** | 브라우저 UA + `Accept: text/html` 로 요청 | **원서버에 없는 분석 비컨이 삽입돼 있었다 — 맨 `curl` 로는 안 보인다** |
| **`html` 입력(2026-09-22)** | 실제 바이너리에 `{"html","url"}` · NDJSON 으로도 | **200 · HIGH 1건 · 단계는 `scan` 하나 · 로그 `input=html`** |
| **`html` 이면 밖으로 안 나가는지** | 가져오기가 불리면 실패하는 테스트 + 변이 6건 | **전부 잡힘**(이름이 찍힌 진짜 실패) |
| **샘플 화면** | 헤드리스 Chrome 으로 버튼 → 모달 → 검사 | **버튼 5 · 모달 안 요소 0개 · DONE · 로그가 "요청"이라 하지 않음** |
| **대조군 — 같은 문자열을 `innerHTML` 로** | 같은 표본 | **form·input·script·base 5개 생성** |
| **설명이 응답에 실리는지(2026-09-22)** | 규칙 25종에 설명 · 나온 코드만 싣는지 · 빈 결과의 `rules` | **실림 · 나온 코드와 개수 일치 · `{}`(null 아님)** |
| **화면에서 펼쳐지는지** | 헤드리스 Chrome 으로 발견 행을 누른다 | **그 행만 열림 · 두 칸(왜·어떻게) · 다시 누르면 닫힘 · 설명이 요소로 해석됨 0개** |

**확인하지 못한 것**

| 항목 | 이유 |
|---|---|
| ~~4절 CSP 가 브라우저에서 실제로 무엇을 막는지~~ | **2026-09-22 에 헤드리스 Chrome 으로 확인했다**(위 표). 남은 것은 `frame-ancestors`·`form-action` 처럼 **위반을 일으켜야 보이는 지시어** — 아직 일부러 어겨 보지 않았다 |
| `always` 가 없을 때 오류 응답에서 헤더가 빠지는지 · `location` 의 `add_header` 가 상위 헤더를 지우는지 | nginx 문서 동작. `always` 를 붙인 상태만 쟀다 |
| jsdom 에서 `onerror` 가 실제로 실행되는지 | jsdom 은 이미지를 불러오지 않는다. **실행 가능한 요소가 만들어지는가**를 확인했다 |
| 실제 Cloudflare 를 거친 **속도 제한** | 운영에서 재려면 스스로를 429 로 만들어야 한다. 헤더를 믿는 설정과 믿지 않는 설정으로 동작 방식만 확인했다(위 표). 응답 내용이 Cloudflare 를 거쳐 온다는 것 자체는 2026-09-22 에 확인했다 |
| `mem_limit`·`pids_limit`·`rate` 값의 적정성 | 부하를 걸어 재지 않았다. 시작값이다 |
| 악성 샘플을 실은 페이지가 **세이프브라우징·백신에 어떻게 보이는지** | 잴 방법이 없다. 대신 위험을 줄였다 — 우리 시그니처 17개 대조 **0건** · 문서 전용 주소만(`example.*` · `203.0.113.0/24`) · **페이지가 아니라 `application/json` 으로만 나간다**(크롤러가 따라갈 악성 페이지 주소가 없다) |
