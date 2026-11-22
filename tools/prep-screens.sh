#!/usr/bin/env bash
# prep-screens.sh - run ON THE VM. Cleans screenshots before they go online.
#   ./tools/prep-screens.sh ~/Pictures/lab-shots
# - only accepts the expected file names (00-lab-page.png, 01-securityheaders.png ... 12-lynis.png)
# - strips metadata, limits width to 1600 px  (needs: sudo apt install imagemagick)
# - if tesseract is installed (sudo apt install tesseract-ocr), OCR-scans each image for leaks
# Output: ./ready/ (same names). Nothing is uploaded.
set -Eeuo pipefail
IN="${1:?usage: prep-screens.sh <folder with png files>}"
OUT="./ready"; mkdir -p "$OUT"
EXPECTED="00-lab-page 01-securityheaders 02-ssllabs 03-observatory 04-ufw 05-kali-ssh-denied 06-kali-catchall 07-outside-checks 08-fail2ban 09-incident1 10-incident2 11-security-check 12-lynis"
if command -v magick >/dev/null; then IM=(magick); elif command -v convert >/dev/null; then IM=(convert); else
  echo "ImageMagick missing: sudo apt install imagemagick"; exit 1; fi
OCR=0; command -v tesseract >/dev/null && OCR=1 || echo "(tesseract not installed - skipping OCR leak scan; check each image by eye)"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
load_env() {  # read KEY="value" lines as DATA - never execute the file (no "source")
  local line re='^(HOME_IP_PREFIX|HOME_NET|ADMIN_USER|SERVER_IP|FAMILY_DOMAIN)="?([A-Za-z0-9./:_-]*)"?[[:space:]]*(#.*)?$'
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line =~ $re ]] && printf -v "${BASH_REMATCH[1]}" '%s' "${BASH_REMATCH[2]}"
  done < "$1"
}
[[ -r "$HERE/local.env" ]] && load_env "$HERE/local.env" || { echo "missing $HERE/local.env"; exit 1; }
q() { printf '%s' "$1" | sed 's/[.[\*^$|]/\\&/g'; }
LEAK="$(q "$HOME_IP_PREFIX")|$(q "${HOME_IP_PREFIX//./-}")|SHA256:[A-Za-z0-9+/]{6}|$(q "$ADMIN_USER")@|/home/$(q "$ADMIN_USER")|AAAAC3Nza|$(q "${FAMILY_DOMAIN%%.*}")|@gmail|@walla"
problems=0
for name in $EXPECTED; do
  src="$IN/$name.png"
  if [[ ! -f "$src" ]]; then echo "  -      $name.png (missing - fine if you skip it)"; continue; fi
  "${IM[@]}" "$src" -strip -resize '1600x>' "$OUT/$name.png"
  msg="ok"; size="$(du -k "$OUT/$name.png" | cut -f1)K"
  if [[ $OCR -eq 1 ]]; then
    hits="$(tesseract "$OUT/$name.png" - 2>/dev/null | grep -oE "$LEAK" | sort -u | tr '\n' ' ' || true)"
    [[ -n "$hits" ]] && { msg="POSSIBLE LEAK: $hits (removed from ready/)"; problems=$((problems+1)); rm -f "$OUT/$name.png"; }
  fi
  printf '  %-6s %-28s %s\n' "$size" "$name.png" "$msg"
done
for f in "$IN"/*.png; do
  b="$(basename "$f" .png)"; [[ " $EXPECTED " == *" $b "* ]] || echo "  ignored (unexpected name): $b.png"
done
[[ $problems -gt 0 ]] && { echo "Fix or re-take the flagged images before uploading."; exit 1; }
echo "Ready in $OUT/. Review each image once more by eye."
