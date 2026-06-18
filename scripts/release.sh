#!/usr/bin/env bash
#
# release.sh — build and publish a Xray-core release to GitHub.
#
# It mirrors the canonical upstream workflow (.github/workflows/release.yml):
#   * cross-compiles the same architecture matrix,
#   * uses the same ldflags / build-id injection,
#   * packages Xray-<friendly-name>.zip archives with geo data, README & LICENSE,
#   * emits md5/sha1/sha256/sha512 .dgst checksums,
#   * tags the version, creates the GitHub release and uploads every asset.
#
# Secrets (GITHUB_TOKEN, owner/repo, optional geo URLs) are read from a .env
# file in the repo root. See .env.example.
#
# Usage:
#   scripts/release.sh [vX.Y.Z] [options]
#
# Options:
#   -v, --version <ver>   Release version (default: derived from core/core.go).
#       --targets <list>  Space/comma list of goos/goarch[/goarm] to build a
#                         subset, e.g. "linux/amd64,darwin/arm64". Default: full.
#       --draft           Create the GitHub release as a draft.
#       --prerelease      Mark the GitHub release as a pre-release.
#       --fetch-geo       Download geoip.dat/geosite.dat if missing.
#       --no-tag          Do not create/push a git tag.
#       --no-publish      Build & package only; skip GitHub release/upload.
#       --clean           Remove the dist/ directory before building.
#       --allow-dirty     Permit building from a dirty working tree.
#   -h, --help            Show this help.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Paths & logging
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
RESOURCES_DIR="${ROOT_DIR}/resources"

if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_INFO=$'\033[36m'; C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'
else
  C_RESET=""; C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""
fi
log()  { printf '%s==>%s %s\n' "${C_INFO}" "${C_RESET}" "$*"; }
ok()   { printf '%s ok %s %s\n' "${C_OK}" "${C_RESET}" "$*"; }
warn() { printf '%swarn%s %s\n' "${C_WARN}" "${C_RESET}" "$*" >&2; }
die()  { printf '%serr %s %s\n' "${C_ERR}" "${C_RESET}" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Defaults & option parsing
# ---------------------------------------------------------------------------
VERSION=""
TARGETS_FILTER=""
DRAFT="false"
PRERELEASE="false"
FETCH_GEO="false"
DO_TAG="true"
DO_PUBLISH="true"
DO_CLEAN="false"
ALLOW_DIRTY="false"

usage() { sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--version)   VERSION="${2:?}"; shift 2 ;;
    --targets)      TARGETS_FILTER="${2:?}"; shift 2 ;;
    --draft)        DRAFT="true"; shift ;;
    --prerelease)   PRERELEASE="true"; shift ;;
    --fetch-geo)    FETCH_GEO="true"; shift ;;
    --no-tag)       DO_TAG="false"; shift ;;
    --no-publish)   DO_PUBLISH="false"; shift ;;
    --clean)        DO_CLEAN="true"; shift ;;
    --allow-dirty)  ALLOW_DIRTY="true"; shift ;;
    -h|--help)      usage; exit 0 ;;
    v[0-9]*|[0-9]*) VERSION="$1"; shift ;;
    *)              die "unknown argument: $1 (try --help)" ;;
  esac
done

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
for bin in go git zip openssl curl python3; do
  command -v "$bin" >/dev/null 2>&1 || die "required tool not found: $bin"
done

# ---------------------------------------------------------------------------
# Load .env
# ---------------------------------------------------------------------------
ENV_FILE="${ROOT_DIR}/.env"
if [[ -f "${ENV_FILE}" ]]; then
  log "Loading ${ENV_FILE}"
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
else
  warn ".env not found at ${ENV_FILE} (copy .env.example -> .env)"
fi

GITHUB_TOKEN="${GITHUB_TOKEN:-}"

# Derive owner/repo from .env or the git 'origin' remote.
GITHUB_OWNER="${GITHUB_OWNER:-}"
GITHUB_REPO="${GITHUB_REPO:-}"
if [[ -z "${GITHUB_OWNER}" || -z "${GITHUB_REPO}" ]]; then
  origin_url="$(git -C "${ROOT_DIR}" remote get-url origin 2>/dev/null || true)"
  if [[ "${origin_url}" =~ github\.com[:/]+([^/]+)/([^/.]+) ]]; then
    GITHUB_OWNER="${GITHUB_OWNER:-${BASH_REMATCH[1]}}"
    GITHUB_REPO="${GITHUB_REPO:-${BASH_REMATCH[2]}}"
  fi
fi

# Geo data sources (override in .env if you prefer a different rule set).
GEOIP_URL="${GEOIP_URL:-https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat}"
GEOSITE_URL="${GEOSITE_URL:-https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat}"

# ---------------------------------------------------------------------------
# Version resolution
# ---------------------------------------------------------------------------
version_from_source() {
  local x y z
  x="$(grep -oE 'Version_x byte = [0-9]+' "${ROOT_DIR}/core/core.go" | grep -oE '[0-9]+')"
  y="$(grep -oE 'Version_y byte = [0-9]+' "${ROOT_DIR}/core/core.go" | grep -oE '[0-9]+')"
  z="$(grep -oE 'Version_z byte = [0-9]+' "${ROOT_DIR}/core/core.go" | grep -oE '[0-9]+')"
  [[ -n "$x" && -n "$y" && -n "$z" ]] || die "cannot parse version from core/core.go"
  printf 'v%s.%s.%s' "$x" "$y" "$z"
}

if [[ -z "${VERSION}" ]]; then
  VERSION="$(version_from_source)"
fi
[[ "${VERSION}" == v* ]] || VERSION="v${VERSION}"
TAG="${VERSION}"
log "Release version: ${VERSION}"

# ---------------------------------------------------------------------------
# Working-tree & build metadata
# ---------------------------------------------------------------------------
if [[ "${ALLOW_DIRTY}" != "true" ]]; then
  if [[ -n "$(git -C "${ROOT_DIR}" status --porcelain)" ]]; then
    die "working tree is dirty; commit/stash first or pass --allow-dirty"
  fi
fi
COMMIT="$(git -C "${ROOT_DIR}" describe --always --dirty)"
LDFLAGS_VERSION="-X github.com/xtls/xray-core/core.build=${COMMIT}"
log "Build metadata: core.build=${COMMIT}"

# ---------------------------------------------------------------------------
# Build matrix  (mirrors .github/workflows/release.yml)
# Each line: GOOS GOARCH GOARM   (GOARM empty when not applicable)
# ---------------------------------------------------------------------------
read -r -d '' MATRIX <<'EOF' || true
windows amd64
windows 386
windows arm64
freebsd amd64
freebsd 386
freebsd arm64
freebsd arm 7
openbsd amd64
openbsd 386
openbsd arm64
openbsd arm 7
linux amd64
linux 386
linux arm64
linux arm 7
linux arm 6
linux arm 5
linux riscv64
linux loong64
linux mips64
linux mips64le
linux mipsle
linux mips
linux ppc64
linux ppc64le
linux s390x
darwin amd64
darwin arm64
EOF

# Android requires the NDK (CGO). Opt in with INCLUDE_ANDROID=1 + ANDROID_NDK_HOME.
if [[ "${INCLUDE_ANDROID:-0}" == "1" ]]; then
  MATRIX+=$'\nandroid arm64\nandroid amd64'
fi

# Friendly asset name for "$GOOS-$GOARCH$GOARM" (upstream friendly-filenames.json).
# Implemented as a case (not an associative array) to run on macOS bash 3.2.
friendly_name() {
  case "$1" in
    android-arm64)   echo android-arm64-v8a ;;
    android-amd64)   echo android-amd64 ;;
    darwin-amd64)    echo macos-64 ;;
    darwin-arm64)    echo macos-arm64-v8a ;;
    freebsd-386)     echo freebsd-32 ;;
    freebsd-amd64)   echo freebsd-64 ;;
    freebsd-arm64)   echo freebsd-arm64-v8a ;;
    freebsd-arm7)    echo freebsd-arm32-v7a ;;
    linux-386)       echo linux-32 ;;
    linux-amd64)     echo linux-64 ;;
    linux-arm5)      echo linux-arm32-v5 ;;
    linux-arm6)      echo linux-arm32-v6 ;;
    linux-arm7)      echo linux-arm32-v7a ;;
    linux-arm64)     echo linux-arm64-v8a ;;
    linux-mips64le)  echo linux-mips64le ;;
    linux-mips64)    echo linux-mips64 ;;
    linux-mipsle)    echo linux-mips32le ;;
    linux-mips)      echo linux-mips32 ;;
    linux-ppc64le)   echo linux-ppc64le ;;
    linux-ppc64)     echo linux-ppc64 ;;
    linux-riscv64)   echo linux-riscv64 ;;
    linux-loong64)   echo linux-loong64 ;;
    linux-s390x)     echo linux-s390x ;;
    openbsd-386)     echo openbsd-32 ;;
    openbsd-amd64)   echo openbsd-64 ;;
    openbsd-arm64)   echo openbsd-arm64-v8a ;;
    openbsd-arm7)    echo openbsd-arm32-v7a ;;
    windows-386)     echo windows-32 ;;
    windows-amd64)   echo windows-64 ;;
    windows-arm64)   echo windows-arm64-v8a ;;
    *)               echo "" ;;
  esac
}

# Does this target pass the --targets filter? (empty filter => everything)
target_selected() {
  local goos="$1" goarch="$2" goarm="$3"
  [[ -z "${TARGETS_FILTER}" ]] && return 0
  local key="${goos}/${goarch}"; [[ -n "${goarm}" ]] && key+="/${goarm}"
  local item
  for item in ${TARGETS_FILTER//,/ }; do
    [[ "${item}" == "${goos}/${goarch}" || "${item}" == "${key}" ]] && return 0
  done
  return 1
}

# ---------------------------------------------------------------------------
# Geo data
# ---------------------------------------------------------------------------
prepare_geo() {
  mkdir -p "${RESOURCES_DIR}"
  local f url
  for f in geoip geosite; do
    if [[ -s "${RESOURCES_DIR}/${f}.dat" ]]; then
      continue
    fi
    if [[ "${FETCH_GEO}" == "true" ]]; then
      url="GEOIP_URL"; [[ "$f" == geosite ]] && url="GEOSITE_URL"
      log "Downloading ${f}.dat from ${!url}"
      curl -fsSL "${!url}" -o "${RESOURCES_DIR}/${f}.dat" || die "failed to download ${f}.dat"
    fi
  done
  if [[ -s "${RESOURCES_DIR}/geoip.dat" && -s "${RESOURCES_DIR}/geosite.dat" ]]; then
    HAVE_GEO="true"
  else
    HAVE_GEO="false"
    warn "geoip.dat/geosite.dat not found; archives will omit geo data (use --fetch-geo to include)"
  fi
}

# ---------------------------------------------------------------------------
# Build + package one target
# ---------------------------------------------------------------------------
build_one() {
  local goos="$1" goarch="$2" goarm="$3"
  local key="${goos}-${goarch}${goarm}"
  local friendly; friendly="$(friendly_name "${key}")"
  [[ -n "${friendly}" ]] || die "no friendly name for ${key}; update friendly_name()"

  local stage="${DIST_DIR}/stage/Xray-${friendly}"
  rm -rf "${stage}"; mkdir -p "${stage}"

  local binname="xray"
  [[ "${goos}" == "windows" ]] && binname="xray.exe"

  local gcflags="all=-l=4"
  [[ "${goarch}" == "mips" || "${goarch}" == "mipsle" ]] && gcflags="-l=4"

  log "Building ${friendly} (GOOS=${goos} GOARCH=${goarch} GOARM=${goarm:-} )"

  local -a env=(CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}")
  [[ -n "${goarm}" ]] && env+=(GOARM="${goarm}")

  # Android: cross-compile with the NDK clang (CGO required).
  if [[ "${goos}" == "android" ]]; then
    [[ -n "${ANDROID_NDK_HOME:-}" ]] || die "android target needs ANDROID_NDK_HOME"
    local cc
    case "${goarch}" in
      arm64) cc="aarch64-linux-android24-clang" ;;
      amd64) cc="x86_64-linux-android24-clang" ;;
      *) die "unsupported android goarch: ${goarch}" ;;
    esac
    local ndk_bin
    ndk_bin="$(echo "${ANDROID_NDK_HOME}"/toolchains/llvm/prebuilt/*/bin)"
    env=(CGO_ENABLED=1 GOOS=android GOARCH="${goarch}" CC="${ndk_bin}/${cc}")
  fi

  ( cd "${ROOT_DIR}" && env "${env[@]}" go build \
      -o "${stage}/${binname}" \
      -trimpath -buildvcs=false \
      -gcflags="${gcflags}" \
      -ldflags="${LDFLAGS_VERSION} -s -w -buildid=" \
      -v ./main )

  # MIPS/MIPSLE: also ship a soft-float binary, like upstream.
  if [[ "${goarch}" == "mips" || "${goarch}" == "mipsle" ]]; then
    ( cd "${ROOT_DIR}" && env CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" GOMIPS=softfloat go build \
        -o "${stage}/xray_softfloat" \
        -trimpath -buildvcs=false \
        -gcflags="${gcflags}" \
        -ldflags="${LDFLAGS_VERSION} -s -w -buildid=" \
        -v ./main )
  fi

  # Bundled assets.
  if [[ "${HAVE_GEO}" == "true" ]]; then
    cp -f "${RESOURCES_DIR}/geoip.dat" "${RESOURCES_DIR}/geosite.dat" "${stage}/"
  fi
  cp -f "${ROOT_DIR}/README.md" "${stage}/README.md"
  cp -f "${ROOT_DIR}/LICENSE" "${stage}/LICENSE"

  # Windows convenience launchers (match upstream).
  if [[ "${goos}" == "windows" ]]; then
    printf 'CreateObject("Wscript.Shell").Run "xray.exe -config config.json",0\n' > "${stage}/xray_no_window.vbs"
    printf 'Start-Process -FilePath ".\\xray.exe" -ArgumentList "-config .\\config.json" -WindowStyle Hidden\n' > "${stage}/xray_no_window.ps1"
  fi

  # Zip + checksums.
  local zip="${DIST_DIR}/Xray-${friendly}.zip"
  rm -f "${zip}" "${zip}.dgst"
  ( cd "${stage}" && touch -mt "$(date +%Y01010000)" ./* 2>/dev/null || true
    zip -9qr "${zip}" . )
  local m
  for m in md5 sha1 sha256 sha512; do
    openssl dgst -"${m}" "${zip}" | sed 's/([^)]*)//g' >> "${zip}.dgst"
  done
  ok "Packaged $(basename "${zip}")"
  printf '%s\n' "${friendly}" >> "${DIST_DIR}/.built"
}

# ---------------------------------------------------------------------------
# GitHub REST helpers
# ---------------------------------------------------------------------------
API="https://api.github.com"
UPLOADS="https://uploads.github.com"

gh_api() {  # method path [json-body]
  local method="$1" path="$2" body="${3:-}"
  local -a args=(-sS -X "${method}"
    -H "Authorization: Bearer ${GITHUB_TOKEN}"
    -H "Accept: application/vnd.github+json"
    -H "X-GitHub-Api-Version: 2022-11-28")
  [[ -n "${body}" ]] && args+=(-H "Content-Type: application/json" -d "${body}")
  curl "${args[@]}" "${API}${path}"
}

json_get() { python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get(sys.argv[1],"")) if isinstance(d,dict) else print("")' "$1"; }

publish_release() {
  [[ -n "${GITHUB_TOKEN}" ]] || die "GITHUB_TOKEN is empty (set it in .env)"
  [[ -n "${GITHUB_OWNER}" && -n "${GITHUB_REPO}" ]] || die "cannot determine GitHub owner/repo (set GITHUB_OWNER/GITHUB_REPO in .env)"
  local repo="/repos/${GITHUB_OWNER}/${GITHUB_REPO}"
  log "Publishing to ${GITHUB_OWNER}/${GITHUB_REPO} @ ${TAG}"

  # Find existing release for this tag, else create one.
  local resp release_id
  resp="$(gh_api GET "${repo}/releases/tags/${TAG}")"
  release_id="$(printf '%s' "${resp}" | json_get id)"

  if [[ -z "${release_id}" || "${release_id}" == "None" ]]; then
    local notes body
    notes="$(release_notes)"
    body="$(python3 -c 'import json,sys;print(json.dumps({"tag_name":sys.argv[1],"name":sys.argv[2],"body":sys.argv[3],"draft":sys.argv[4]=="true","prerelease":sys.argv[5]=="true"}))' \
      "${TAG}" "Xray ${VERSION}" "${notes}" "${DRAFT}" "${PRERELEASE}")"
    resp="$(gh_api POST "${repo}/releases" "${body}")"
    release_id="$(printf '%s' "${resp}" | json_get id)"
    [[ -n "${release_id}" && "${release_id}" != "None" ]] || die "failed to create release: ${resp}"
    ok "Created release id=${release_id}"
  else
    ok "Reusing existing release id=${release_id}"
  fi

  # Map of existing asset name -> id, so re-runs overwrite cleanly.
  local assets_json
  assets_json="$(gh_api GET "${repo}/releases/${release_id}/assets?per_page=100")"

  local f name existing
  for f in "${DIST_DIR}"/*.zip "${DIST_DIR}"/*.zip.dgst; do
    [[ -e "${f}" ]] || continue
    name="$(basename "${f}")"
    existing="$(printf '%s' "${assets_json}" | python3 -c \
      'import sys,json;n=sys.argv[1];print(next((str(a["id"]) for a in json.load(sys.stdin) if a["name"]==n),""))' "${name}")"
    if [[ -n "${existing}" ]]; then
      gh_api DELETE "${repo}/releases/assets/${existing}" >/dev/null || true
    fi
    log "Uploading ${name}"
    curl -sS -X POST \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      -H "Content-Type: application/octet-stream" \
      --data-binary @"${f}" \
      "${UPLOADS}${repo}/releases/${release_id}/assets?name=${name}" >/dev/null \
      || die "upload failed: ${name}"
  done
  ok "All assets uploaded"
}

release_notes() {
  local prev
  prev="$(git -C "${ROOT_DIR}" describe --tags --abbrev=0 "${TAG}^" 2>/dev/null || true)"
  printf 'Xray-core %s\n\n' "${VERSION}"
  if [[ -n "${prev}" ]]; then
    printf '## Changes since %s\n\n' "${prev}"
    git -C "${ROOT_DIR}" log --no-merges --pretty='- %s (%h)' "${prev}..${TAG}"
  else
    printf '## Commits\n\n'
    git -C "${ROOT_DIR}" log --no-merges --pretty='- %s (%h)' -n 30 "${TAG}"
  fi
}

# ---------------------------------------------------------------------------
# Git tag
# ---------------------------------------------------------------------------
ensure_tag() {
  [[ "${DO_TAG}" == "true" ]] || { log "Skipping tag (--no-tag)"; return; }
  if git -C "${ROOT_DIR}" rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
    ok "Tag ${TAG} already exists"
  else
    log "Creating tag ${TAG}"
    git -C "${ROOT_DIR}" tag -a "${TAG}" -m "Xray ${VERSION}"
  fi
  if [[ "${DO_PUBLISH}" == "true" ]]; then
    log "Pushing tag ${TAG} to origin"
    git -C "${ROOT_DIR}" push origin "refs/tags/${TAG}"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  [[ "${DO_CLEAN}" == "true" ]] && { log "Cleaning ${DIST_DIR}"; rm -rf "${DIST_DIR}"; }
  mkdir -p "${DIST_DIR}"
  rm -f "${DIST_DIR}/.built"

  prepare_geo
  ensure_tag

  local built=0 line goos goarch goarm
  while read -r goos goarch goarm; do
    [[ -z "${goos:-}" ]] && continue
    target_selected "${goos}" "${goarch}" "${goarm}" || continue
    build_one "${goos}" "${goarch}" "${goarm}"
    built=$((built + 1))
  done <<< "${MATRIX}"

  rm -rf "${DIST_DIR}/stage"
  [[ "${built}" -gt 0 ]] || die "no targets matched --targets '${TARGETS_FILTER}'"
  ok "Built ${built} target(s); artifacts in ${DIST_DIR}"

  if [[ "${DO_PUBLISH}" == "true" ]]; then
    publish_release
    ok "Release ${VERSION} published: https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/releases/tag/${TAG}"
  else
    log "Skipping publish (--no-publish). Built archives:"
    ls -1 "${DIST_DIR}"/*.zip
  fi
}

main "$@"
