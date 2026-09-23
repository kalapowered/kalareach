#!/bin/sh
# A scripted agent: the contact tools spoken the way an installed agent speaks them, by a small
# shell program standing in for a coding agent.
#
# It starts `kr agent-tools --stdio` as its own child and talks to it over that child's standard
# streams, one JSON-RPC message per line, as an agent talks to a tool server it was configured
# with. It asks its person one question with `ask_user`, waits on that same question with
# `wait_for_answer` until the person answers, and says what the answer was. Then it goes on
# running, and acts only when the test opens one of the gates beside it, so nothing here runs on a
# clock of its own.
#
# `agent.conf`, beside this file, is its tool configuration: the `kr` to start and the host
# directories to start it with. What it writes goes beside it too.

set -u

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=/dev/null
. "$here/agent.conf"

printf '%s\n' "$$" > "$here/agent.pid"

rm -f "$here/to-tools" "$here/from-tools"
mkfifo "$here/to-tools" "$here/from-tools" || exit 70

# The tool server is this agent's own child. The host directories reach it and nothing else.
# shellcheck disable=SC2154 # kr, kr_runtime_dir and kr_state_dir are set by agent.conf
KR_RUNTIME_DIR=$kr_runtime_dir KR_STATE_DIR=$kr_state_dir \
  "$kr" agent-tools --stdio < "$here/to-tools" > "$here/from-tools" &
tools=$!
printf '%s\n' "$tools" > "$here/tools.pid"
exec 3> "$here/to-tools" 4< "$here/from-tools"

send() {
  printf '%s\n' "$1" >&3
}

# Reads messages until the reply to request $1 arrives, and prints that reply. A reply carries the
# request's identifier followed by its result or its error; anything else is passed over.
reply_to() {
  while IFS= read -r line <&4; do
    case $line in
      *"\"id\":$1,\"result\":"* | *"\"id\":$1,\"error\":"*)
        printf '%s\n' "$line"
        return 0
        ;;
    esac
  done
  return 1
}

# One string field of a reply's structured result. The text copy of the same result is escaped
# inside a string, so a quote followed by the field's name is only ever the structured one.
field() {
  printf '%s\n' "$2" | sed -n "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/p"
}

# Writes a reply where the test reads it, whole or not at all.
keep() {
  printf '%s\n' "$2" > "$here/$1.partial" && mv "$here/$1.partial" "$here/$1"
}

send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"scripted-agent","version":"1.0.0"}}}'
reply_to 1 > /dev/null || { echo "the tool server did not answer the handshake"; exit 71; }
send '{"jsonrpc":"2.0","method":"notifications/initialized"}'

send '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ask_user","arguments":{"request_id":"release-name","agent_name":"scripted agent","context":"The release is tagged once it has a name.","question":"What should the release be called?","type":"input"}}}'
asked=$(reply_to 2) || { echo "ask_user was not answered"; exit 72; }
keep asked.json "$asked"
question=$(field question_id "$asked")
token=$(field caller_token "$asked")
if [ -z "$question" ] || [ -z "$token" ]; then
  printf 'ask_user created no question: %s\n' "$asked"
  exit 73
fi
printf 'the agent asked question %s\n' "$question"

# The same question until somebody answers it. A wait that runs out returns the question still
# pending, and the agent waits on it again rather than asking again.
id=3
while :; do
  send "{\"jsonrpc\":\"2.0\",\"id\":$id,\"method\":\"tools/call\",\"params\":{\"name\":\"wait_for_answer\",\"arguments\":{\"question_id\":\"$question\",\"caller_token\":\"$token\",\"wait_seconds\":30}}}"
  waited=$(reply_to "$id") || { echo "wait_for_answer was not answered"; exit 74; }
  state=$(field state "$waited")
  [ "$state" = pending ] || break
  id=$((id + 1))
done
keep answered.json "$waited"
if [ "$state" != answered ]; then
  printf 'the question ended %s\n' "$state"
  exit 75
fi
printf 'the agent was answered: %s\n' "$(field text "$waited")"

# Still running, and waiting for nothing but the test.
read -r _ < "$here/go-on"
printf 'the agent kept running after the detach\n'
# Two things that were events when they happened and are no part of the screen: a clipboard write
# and a bell. Then a line that is on the screen for a moment and is gone again.
printf '\033]52;c;aGVsbG8=\033\134'
printf '\a'
printf 'a line the screen no longer shows'
printf '\r\033[2K'
printf 'the screen as it is now\n'

read -r _ < "$here/finish"
# Closing the tool server's input is how an agent ends it, and the status is the one the kernel
# reports for it.
exec 3>&-
wait "$tools"
printf 'the tool server exited with status %s\n' "$?"
exec 4<&-
rm -f "$here/to-tools" "$here/from-tools"
exit 0
