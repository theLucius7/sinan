#!/usr/bin/env bash
# Sinan's current host curl boundary; upstream sources and full licenses stay embedded.
# This wrapper does not replace or relicense the retained AGPL source snapshots.
set -euo pipefail
umask 077
upload_url=https://api.nodequality.com/api/v1/record
upload=0
for argument in "$@"; do
  [[ $argument != "$upload_url" ]] || upload=1
done
if [[ $upload == 0 ]]; then
  exec python3 "$SINAN_CHAIN_HELPER" serve "$SINAN_CHAIN_DIRECTORY" "$@"
fi
# A permitted destination anywhere in argv must not authorize other URLs,
# curl configuration, file reads, redirects or a second transfer. Keep the
# exact POST shape in the canonical pinned entrypoint and capture stdin once.
if [[ $# != 5 || $1 != -X || $2 != POST || $3 != --data-binary || $4 != @- || $5 != "$upload_url" ]]; then
  printf '%s\n' 'Error: unsupported public report request; online fallback is forbidden' >&2
  exit 70
fi
python3 "$SINAN_REPORT_HELPER" capture "$SINAN_REPORT_WORKSPACE"
if [[ ${SINAN_UPLOAD_REPORT:-false} != true ]]; then
  printf '%s\n' 'disabled' > "$SINAN_REPORT_WORKSPACE/upload-disabled.txt"
  printf '%s\n' 'Public report upload is disabled.'
  exit 0
fi
set +e
# --disable must be first: an inherited curlrc cannot add destinations,
# payloads, browser headers or retries to the one explicitly authorized POST.
"$SINAN_REAL_CURL" --disable --proto '=https' --proto-redir '=https' \
  --connect-timeout 15 --max-time 60 --max-filesize 65536 \
  --write-out $'\nSINAN_RESPONSE_STATUS:%{http_code}' \
  -X POST --data-binary "@$SINAN_REPORT_WORKSPACE/upload.base64" "$upload_url" \
  | python3 "$SINAN_REPORT_HELPER" response "$SINAN_REPORT_WORKSPACE"
statuses=("${PIPESTATUS[@]}")
set -e
[[ ${statuses[1]} == 0 ]] || exit "${statuses[1]}"
exit "${statuses[0]}"
