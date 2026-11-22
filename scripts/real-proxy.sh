#!/usr/bin/env bash
# Runs a squid on the loopback for the cases that name a real proxy, and stops it.
#
#   scripts/real-proxy.sh start <run folder> basic|digest|bump
#   scripts/real-proxy.sh stop <run folder>
#
# The run folder is made for the run and holds everything the proxy needs: its configuration, its
# access log, a password file and a credential file made for this run (mode 0600, one
# `user:password` line), and `env.sh`, which names the proxy to the cases:
#
#   KR_REAL_PROXY                    the proxy's origin, for example http://127.0.0.1:41230
#   KR_REAL_PROXY_CREDENTIAL_FILE    the credential file
#   KR_REAL_PROXY_ACCESS_LOG         the proxy's own access log
#
# `digest` writes the same three names with DIGEST after the first two words: KR_REAL_PROXY_DIGEST,
# KR_REAL_PROXY_DIGEST_CREDENTIAL_FILE and KR_REAL_PROXY_DIGEST_ACCESS_LOG, so one run can name both.
#
# `bump` intercepts TLS with a certificate authority made for the run (`ca.pem`, its key `ca.key`
# and the authority's DER form `ca.der`, all in the run folder) and asks for no login. It listens on
# two ports: the origin KR_REAL_PROXY_BUMP passes a WebSocket upgrade and KR_REAL_PROXY_BUMP_BLOCKING
# answers it with 403. KR_REAL_PROXY_BUMP_CA_FILE and KR_REAL_PROXY_BUMP_ACCESS_LOG complete the names.
#
# `basic` asks every CONNECT for a user name and password by HTTP Basic. `digest` offers Digest only,
# so it stands for a proxy that asks for a sign-in method this host does not send. Each log line is
# `<time> <client> <method> <target> <status> <result> <user>`, where the user is `-` when the
# request carried none.
#
# SQUID names the squid program (6 or newer; default: squid on the path). SQUID_LIBEXEC names the
# folder of its helpers (basic_ncsa_auth, digest_file_auth); by default it is the `libexec` folder
# next to the program's `sbin` folder, or /usr/lib/squid. SQUID_EXTRA_CONF names a file of further
# directives, appended to the configuration, for a squid whose built-in file locations are not
# where its files are (a relocated copy).
#
# The proxy is started by this script and by nothing else: no service manager is used. `stop`
# reads the process number the script saved, checks that the process runs this folder's
# configuration, and stops that process only.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"

die() {
  echo "real-proxy: $*" >&2
  exit 1
}

squid_program() {
  local program="${SQUID:-squid}"
  command -v "$program" >/dev/null 2>&1 || die "no squid program: set SQUID to one (6 or newer)"
  command -v "$program"
}

libexec_of() {
  local program="$1"
  if [ -n "${SQUID_LIBEXEC:-}" ]; then
    echo "$SQUID_LIBEXEC"
    return
  fi
  local beside
  beside="$(cd "$(dirname "$program")/../libexec" 2>/dev/null && pwd || true)"
  if [ -n "$beside" ] && [ -x "$beside/basic_ncsa_auth" ]; then
    echo "$beside"
  else
    echo /usr/lib/squid
  fi
}

free_port() {
  python3 -I -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

start() {
  local run="$1" mode="$2"
  case "$mode" in basic | digest | bump) ;; *) die "the mode is basic, digest or bump" ;; esac
  case "$run" in /*) ;; *) die "the run folder is an absolute path" ;; esac
  [ ! -e "$run/proxy.pid" ] || die "a proxy was started in $run: stop it first"
  mkdir -p "$run"
  chmod 700 "$run"

  local program libexec port user password
  program="$(squid_program)"
  libexec="$(libexec_of "$program")"
  [ -x "$libexec/basic_ncsa_auth" ] || die "no auth helpers in $libexec: set SQUID_LIBEXEC"
  port="$(free_port)"
  user="user"
  password="$(openssl rand -hex 16)"

  umask 077
  local blockport=""
  if [ "$mode" = bump ]; then
    blockport="$(free_port)"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=a real proxy case authority" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -keyout "$run/ca.key" -out "$run/ca.pem" >"$run/ca.log" 2>&1 || die "no authority: see $run/ca.log"
    openssl x509 -in "$run/ca.pem" -outform der -out "$run/ca.der"
    "$libexec/security_file_certgen" -c -s "$run/ssl_db" -M 4MB >"$run/certgen.log" 2>&1 \
      || die "no certificate database: see $run/certgen.log"
  else
    if [ "$mode" = basic ]; then
      printf '%s' "$password" | openssl passwd -apr1 -stdin | sed "s/^/$user:/" >"$run/passwd"
    else
      printf '%s:%s\n' "$user" "$password" >"$run/passwd"
    fi
    printf '%s:%s\n' "$user" "$password" >"$run/credential"
  fi
  sed -e "s|@RUN@|$run|g" -e "s|@PORT@|$port|g" -e "s|@BLOCKPORT@|$blockport|g" -e "s|@LIBEXEC@|$libexec|g" \
    "$here/real-proxy/$mode.conf" >"$run/squid.conf"
  if [ -n "${SQUID_EXTRA_CONF:-}" ]; then
    cat "$SQUID_EXTRA_CONF" >>"$run/squid.conf"
  fi
  : >"$run/access.log"
  if [ "$mode" = bump ]; then
    {
      echo "export KR_REAL_PROXY_BUMP=http://127.0.0.1:$port"
      echo "export KR_REAL_PROXY_BUMP_BLOCKING=http://127.0.0.1:$blockport"
      echo "export KR_REAL_PROXY_BUMP_CA_FILE=$run/ca.der"
      echo "export KR_REAL_PROXY_BUMP_ACCESS_LOG=$run/access.log"
    } >"$run/env.sh"
  else
    local name=KR_REAL_PROXY
    if [ "$mode" = digest ]; then
      name=KR_REAL_PROXY_DIGEST
    fi
    {
      echo "export $name=http://127.0.0.1:$port"
      echo "export ${name}_CREDENTIAL_FILE=$run/credential"
      echo "export ${name}_ACCESS_LOG=$run/access.log"
    } >"$run/env.sh"
  fi

  "$program" -k parse -f "$run/squid.conf" >"$run/parse.log" 2>&1 \
    || die "squid refuses the configuration: see $run/parse.log"
  nohup "$program" -N -f "$run/squid.conf" >"$run/squid.out" 2>&1 &
  local pid=$!
  echo "$pid" >"$run/proxy.pid"
  disown "$pid" 2>/dev/null || true
  local waited=0
  until python3 -I -c "import socket,sys
s = socket.socket()
s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1', $port)) == 0 else 1)"; do
    kill -0 "$pid" 2>/dev/null || die "squid ended at its start: see $run/squid.out and $run/cache.log"
    waited=$((waited + 1))
    [ "$waited" -lt 100 ] || die "squid did not listen in 20 seconds: see $run/cache.log"
    sleep 0.2
  done
  echo "real-proxy: $mode proxy $pid listening on http://127.0.0.1:$port (run folder $run)"
}

stop() {
  local run="$1"
  [ -f "$run/proxy.pid" ] || die "no proxy was started in $run"
  local pid
  pid="$(cat "$run/proxy.pid")"
  case "$pid" in '' | *[!0-9]*) die "the process number in $run/proxy.pid is not a number" ;; esac
  if kill -0 "$pid" 2>/dev/null; then
    local arguments
    arguments="$(ps -o command= -p "$pid")"
    case "$arguments" in
      *"-f $run/squid.conf"*) ;;
      *) die "process $pid does not run $run/squid.conf: $arguments" ;;
    esac
    kill "$pid"
    local waited=0
    while kill -0 "$pid" 2>/dev/null; do
      waited=$((waited + 1))
      [ "$waited" -lt 100 ] || die "process $pid did not end in 20 seconds"
      sleep 0.2
    done
  fi
  mv "$run/proxy.pid" "$run/proxy.pid.ended"
  echo "real-proxy: stopped $pid"
}

case "${1:-}" in
  start) [ $# -eq 3 ] || die "usage: real-proxy.sh start <run folder> basic|digest|bump"; start "$2" "$3" ;;
  stop) [ $# -eq 2 ] || die "usage: real-proxy.sh stop <run folder>"; stop "$2" ;;
  *) die "usage: real-proxy.sh start <run folder> basic|digest|bump | stop <run folder>" ;;
esac
