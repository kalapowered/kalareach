# shellcheck shell=bash
# Ending only the processes a script started, by who they are rather than by the number they had.
#
# Sourced by the end-to-end scripts. A process number is not an identity: once the process it named
# has ended and been collected, the kernel hands the number to the next process that starts, and a
# script that signals a number it stored earlier can end somebody else's work. So a script records,
# beside each number, when that process started and the program it runs, and signals the number
# only while the operating system still reports both. A number that now names another process, or
# none, is left alone and said so.
#
# The start time is the kernel's, to the second, and does not change when a process replaces its
# image, so a record taken the moment a background job is forked still holds once that job has
# become the program it was started to run. What remains between the last look and the signal is
# the time it takes to send it.
#
# Written for the bash macOS ships, so no associative arrays: each record is one string,
# "<number>|<started>|<program>", in the array `owned_processes`.

owned_processes=()

# When a process started, as the operating system reports it, or nothing where there is no such
# process.
process_started() {
  LC_ALL=C ps -o lstart= -p "$1" 2>/dev/null | sed -e 's/^ *//' -e 's/ *$//'
}

# The command a process runs, program first, or nothing where there is no such process.
process_command() {
  ps -o command= -p "$1" 2>/dev/null | sed -e 's/^ *//'
}

# remember_process <number> <program>
# Records a process this script started, with the time it started and the program it runs or is
# about to run. A process that has already gone is not recorded: there is nothing of it to end.
remember_process() {
  local started
  started="$(process_started "$1")"
  [ -n "$started" ] || return 0
  record_process "$1" "$started" "$2"
}

# record_process <number> <started> <program>
# Records a process whose start time and program were read where it was started, by whatever
# started it, so the record says what that process was and not what the number names later.
record_process() {
  owned_processes+=("$1|$2|$3")
}

# is_same_process <number> <started> <program>
# Succeeds only while <number> still names a process that started at <started> and runs <program>.
is_same_process() {
  local now command
  now="$(process_started "$1")"
  [ -n "$now" ] && [ "$now" = "$2" ] || return 1
  command="$(process_command "$1")"
  case $command in
    "$3" | "$3 "*) return 0 ;;
    *) return 1 ;;
  esac
}

# end_process <number> <started> <program>
# Signals one recorded process, only while it is still the one that was recorded.
end_process() {
  if is_same_process "$1" "$2" "$3"; then
    kill "$1" 2>/dev/null || true
  elif [ -n "$(process_started "$1")" ]; then
    echo "process $1 is no longer the $3 this run started, so it is left alone:" \
      "$(process_started "$1"), $(process_command "$1")"
  fi
}

# end_owned_processes
# Signals every process this script recorded that is still the one it recorded.
end_owned_processes() {
  local record number started program
  for record in "${owned_processes[@]:-}"; do
    [ -n "$record" ] || continue
    IFS='|' read -r number started program <<<"$record"
    end_process "$number" "$started" "$program"
  done
}
