#!/usr/bin/env bash
#
#   tools/measure.sh       이미 받은 페이지는 그대로 두고 스캔
#   tools/measure.sh -f    모두 다시 받는다
#
set -u
cd "$(dirname "$0")/.."

LIST=tools/sites.txt
DIR=testdata/live
UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
FORCE=${1:-}

mkdir -p "$DIR"
go build -o "$DIR/.scanner" . || exit 1

# 1) 수집 — 병렬 8개
fetch() {
  local name=${1%%|*} url=${1#*|} out
  out="$DIR/$name.html"
  [ "$FORCE" != "-f" ] && [ -s "$out" ] && return
  curl -sSL -m 20 -A "$UA" --compressed -o "$out" "$url" 2>/dev/null
}
export -f fetch
export DIR UA FORCE
grep -v '^#' "$LIST" | grep . | xargs -P 8 -I{} bash -c 'fetch "$@"' _ {}

# 2) 스캔 — 받지 못한 것(차단 페이지 등)은 건너뛴다
findings=$(mktemp)
pages=0
skipped=0
blocked=""
start=$(date +%s)
while IFS='|' read -r name url; do
  [ -z "$name" ] && continue
  f="$DIR/$name.html"
  if [ ! -s "$f" ] || [ "$(wc -c <"$f")" -lt 2000 ]; then
    skipped=$((skipped + 1)) # 차단·리다이렉트로 내용이 없는 것
    blocked="${blocked}${name} "
    continue
  fi
  pages=$((pages + 1))
  # 발견이 있으면 스캐너가 1 로 끝난다 — set -e 를 쓰지 않는 이유다
  "$DIR/.scanner" "$f" "$url" 2>/dev/null | sed "s|^|${name}\t|" >>"$findings"
done < <(grep -v '^#' "$LIST" | grep .)
elapsed=$(($(date +%s) - start))
total=$(grep -c . "$findings" || true)

# 3) 집계
[ "$elapsed" -eq 0 ] && elapsed="1 미만"
echo "스캔 ${pages}쪽 · ${elapsed}초 · 발견 ${total}건"
if [ -n "$blocked" ]; then
  echo "받지 못함 ${skipped}: ${blocked}"
fi
echo
echo "[규칙별]"
grep -oE '\[[a-z-]+\]' "$findings" | sort | uniq -c | sort -rn | sed 's/^/  /'
echo
echo "[심각도별]"
awk '{for (i = 1; i <= NF; i++) if ($i ~ /^(HIGH|MEDIUM|LOW|INFO)$/) { print $i; break }}' "$findings" |
  sort | uniq -c | sort -rn | sed 's/^/  /'
echo
echo "[발견이 많은 페이지]"
cut -f1 "$findings" | sort | uniq -c | sort -rn | head -5 | sed 's/^/  /'

if grep -q ' HIGH ' "$findings"; then
  echo
  echo "[HIGH] 정상 사이트에서 나오면 오탐이다"
  grep ' HIGH ' "$findings" | sed 's/^/  /'
fi
rm -f "$findings"
