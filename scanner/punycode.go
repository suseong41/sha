package scanner

import "strings"

// RFC 3492 punycode 디코딩
const (
	punyBase        = 36
	punyTmin        = 1
	punyTmax        = 26
	punySkew        = 38
	punyDamp        = 700
	punyInitialBias = 72
	punyInitialN    = 128
	punyDelim       = '-'
)

// punyDecode(): "xn--"을 원래 글자로
func punyDecode(label string) (string, bool) {
	if !strings.HasPrefix(strings.ToLower(label), "xn--") {
		return label, true // punycode 아닌 경우
	}
	encoded := label[4:]
	if encoded == "" {
		return "", false // "xn--"뿐
	}
	var output []rune
	if i := strings.LastIndexByte(encoded, punyDelim); i >= 0 {
		for _, r := range encoded[:i] {
			if 0x7F < r {
				return "", false
			}
			output = append(output, r)
		}
		encoded = encoded[i+1:]
	}

	n, bias, pos := rune(punyInitialN), punyInitialBias, 0
	for idx := 0; idx < len(encoded); {
		oldPos, w, k := pos, 1, punyBase
		for {
			if len(encoded) <= idx {
				return "", false
			}
			digit, ok := punyDigit(encoded[idx])
			if !ok {
				return "", false
			}
			idx++
			pos += digit * w
			if pos < 0 || 1024 < len(output) {
				return "", false
			}
			t := k - bias
			switch {

			case t < punyTmin:
				t = punyTmin
			case punyTmax < t:
				t = punyTmax
			}
			if digit < t {
				break
			}
			w *= punyBase - t
			k += punyBase
		}
		bias = punyAdapt(pos-oldPos, len(output)+1, oldPos == 0)
		n += rune(pos / (len(output) + 1))
		pos %= len(output) + 1
		if 0x10FFFF < n || (0xD800 <= n && n <= 0xDFFF) {
			return "", false
		}
		output = append(output, 0)
		copy(output[pos+1:], output[pos:])
		output[pos] = n
		pos++
	}
	return string(output), true
}

// punyDigit(): 글자 하나를 0~35 숫자로, a-z: 0~25, 0-9: 26~35
func punyDigit(c byte) (int, bool) {
	switch {
	case 'a' <= c && c <= 'z':
		return int(c - 'a'), true
	case 'A' <= c && c <= 'Z':
		return int(c - 'A'), true
	case '0' <= c && c <= '9':
		return int(c-'0') + 26, true
	}
	return 0, false
}

// punyAdapt(): 다음 글자의 자릿수 폭을 조정
func punyAdapt(delta, numPoints int, firstTime bool) int {
	if firstTime {
		delta /= punyDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for ((punyBase - punyTmin) * punyTmax / 2) < delta {
		delta /= punyBase - punyTmin
		k += punyBase
	}
	return k + (punyBase-punyTmin+1)*delta/(delta+punySkew)
}
