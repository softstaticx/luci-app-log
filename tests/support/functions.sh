#!/bin/sh
# /lib/functions.sh stand-in for the shell test suite.
#
# The real file is supplied by libubox on OpenWrt. These stubs let the watcher
# run its decision logic without a firewall configuration parser; tests that
# need zones point LOG_VIEWER_FIREWALL_CONFIG at a missing file so the
# configured zone is trusted, or set LOG_VIEWER_FAKE_ZONES to a space-separated
# list of zone names.
set -eu

config_load() {
  CONFIG_SECTIONS=""
  if [ -n "${LOG_VIEWER_FAKE_ZONES:-}" ]; then
    CONFIG_SECTIONS="$LOG_VIEWER_FAKE_ZONES"
  fi
  return 0
}

config_foreach() {
  callback="$1"
  type="$2"
  [ "$#" -ge 2 ] || return 0
  shift 2
  [ "$type" = "zone" ] || return 0
  for section in ${CONFIG_SECTIONS:-}; do
    "$callback" "$section" "$@"
  done
  return 0
}

config_get() {
  # config_get <var> <section> <option> [default]
  var="$1"
  section="$2"
  option="$3"
  default="${4:-}"
  if [ "$option" = "name" ] && [ -z "$default" ]; then
    default="$section"
  fi
  # shellcheck disable=SC2086
  eval "$var=\"\${$var:-$default}\""
}

config_get_bool() {
  config_get "$@"
}
