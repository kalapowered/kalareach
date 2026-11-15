#!/bin/bash
# run-unit.sh OPTIONS -- COMMAND [ARGS...]
#
# The one place that starts an account's command: as a transient service of the system manager
# (`sudo systemd-run`), with the property list below, never from the caller's session. The
# caller's directory, variables, descriptors, standard streams and processes never reach the
# unit: its parent is the manager, its directory is --workdir, its variables are the --env ones
# and a fixed PATH, its input is /dev/null and its output is a file that no account can see.
# The output is printed, behind a fixed prefix and inside a stop-commands bracket, only after
# the unit has ended (replay-log.sh). The launcher exits with the status of `systemd-run --wait`,
# which is the command's own status, or a nonzero status for a signal, a time limit or a failed
# start. With --no-wait it starts the unit and returns; stop-unit.sh ends it and prints its output.
#
# Options (every path and name is an argument; nothing here names a repository):
#   --name NAME            unit name without suffix, [A-Za-z0-9._-]+, not used before in this job
#   --user U --group G     the account
#   --workdir DIR          working directory (absolute)
#   --log-dir DIR          runner-owned folder, mode 0700, that no account can see
#   --runtime-max SECONDS  time limit; the manager ends the unit when it is reached
#   --netns NAME           join /run/netns/NAME (made by make-netns.sh); the guard must pass
#   --host-network         no private namespace (the fetch unit, controls); exactly one of the two
#   --guard PATH           the root-owned guard.sh, required with --netns
#   --bind PATH            writable bind of an account's own folder (repeatable)
#   --bind-ro PATH         read-only bind (repeatable)
#   --env NAME=VALUE       a variable of the unit (repeatable); the unit has no others but PATH
#   --prop NAME=VALUE      one more property, as the runner's trusted code chooses it (repeatable)
#   --type TYPE            service type (default exec); --exit-type cgroup|main
#   --no-wait              start and return
#   --shm tmpfs|inaccessible   private /dev/shm as a tmpfs (default) or made inaccessible
#   --prefix P             replay prefix (default NAME)
#   --dry-run              print the property list and the command, start nothing
# Controls only (a negative control must be able to start a unit that the guard then refuses):
#   --netns-path PATH --netns-inode N   join PATH, expect inode N
#
# Never used here: --pty, --pipe, --scope, --user (the manager's), --same-dir, --shell, -E.
set -u
set -C
umask 077

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

die() {
  echo "run-unit: $*" >&2
  exit 2
}

name='' user='' group='' workdir='' logdir='' guard='' netns='' nspath='' nsinode=''
hostnet=0 wait=1 dry=0 runtime_max='' type=exec exit_type='' prefix='' shm=tmpfs
binds=() robinds=() envs=() props=()

while [ "$#" -gt 0 ]; do
  case $1 in
    --name) [ "$#" -ge 2 ] || die "$1 needs a value"; name=$2; shift 2 ;;
    --user) [ "$#" -ge 2 ] || die "$1 needs a value"; user=$2; shift 2 ;;
    --group) [ "$#" -ge 2 ] || die "$1 needs a value"; group=$2; shift 2 ;;
    --workdir) [ "$#" -ge 2 ] || die "$1 needs a value"; workdir=$2; shift 2 ;;
    --log-dir) [ "$#" -ge 2 ] || die "$1 needs a value"; logdir=$2; shift 2 ;;
    --runtime-max) [ "$#" -ge 2 ] || die "$1 needs a value"; runtime_max=$2; shift 2 ;;
    --netns) [ "$#" -ge 2 ] || die "$1 needs a value"; netns=$2; shift 2 ;;
    --netns-path) [ "$#" -ge 2 ] || die "$1 needs a value"; nspath=$2; shift 2 ;;
    --netns-inode) [ "$#" -ge 2 ] || die "$1 needs a value"; nsinode=$2; shift 2 ;;
    --host-network) hostnet=1; shift ;;
    --guard) [ "$#" -ge 2 ] || die "$1 needs a value"; guard=$2; shift 2 ;;
    --bind) [ "$#" -ge 2 ] || die "$1 needs a value"; binds+=("$2"); shift 2 ;;
    --bind-ro) [ "$#" -ge 2 ] || die "$1 needs a value"; robinds+=("$2"); shift 2 ;;
    --env) [ "$#" -ge 2 ] || die "$1 needs a value"; envs+=("$2"); shift 2 ;;
    --prop) [ "$#" -ge 2 ] || die "$1 needs a value"; props+=("$2"); shift 2 ;;
    --type) [ "$#" -ge 2 ] || die "$1 needs a value"; type=$2; shift 2 ;;
    --exit-type) [ "$#" -ge 2 ] || die "$1 needs a value"; exit_type=$2; shift 2 ;;
    --shm) [ "$#" -ge 2 ] || die "$1 needs a value"; shm=$2; shift 2 ;;
    --prefix) [ "$#" -ge 2 ] || die "$1 needs a value"; prefix=$2; shift 2 ;;
    --no-wait) wait=0; shift ;;
    --dry-run) dry=1; shift ;;
    --) shift; break ;;
    *) die "unknown option $1" ;;
  esac
done

# ---- validation: nothing an account could influence is taken as a name or a path here ----
valid_name() { case $1 in '' | [!A-Za-z0-9]* | *[!A-Za-z0-9._-]*) return 1 ;; esac; [ "${#1}" -le 64 ]; }
valid_path() { case $1 in /* ) ;; *) return 1 ;; esac; case $1 in *[!A-Za-z0-9._/@+=,:-]*) return 1 ;; esac; }

valid_name "$name" || die "--name must match [A-Za-z0-9][A-Za-z0-9._-]* (at most 64)"
valid_name "$user" || die "--user is not a plain account name"
valid_name "$group" || die "--group is not a plain account name"
valid_path "$workdir" || die "--workdir must be a plain absolute path"
valid_path "$logdir" || die "--log-dir must be a plain absolute path"
[ -d "$logdir" ] && [ ! -L "$logdir" ] || die "--log-dir is not a folder"
case $runtime_max in '' | *[!0-9]*) die "--runtime-max must be a number of seconds" ;; esac
[ "$runtime_max" -ge 1 ] || die "--runtime-max must be at least 1"
case $type in exec | forking | oneshot | simple) ;; *) die "--type must be exec, forking, oneshot or simple" ;; esac
case $exit_type in '' | cgroup | main) ;; *) die "--exit-type must be cgroup or main" ;; esac
case $shm in tmpfs | inaccessible) ;; *) die "--shm must be tmpfs or inaccessible" ;; esac
[ -n "$prefix" ] || prefix=$name
valid_name "$prefix" || die "--prefix is not plain"
for p in "${binds[@]+"${binds[@]}"}" "${robinds[@]+"${robinds[@]}"}"; do
  valid_path "$p" || die "a bind path is not plain: $p"
done
for e in "${envs[@]+"${envs[@]}"}"; do
  case $e in
    [A-Za-z_]*=*) ;;
    *) die "--env needs NAME=VALUE, never a bare name: $e" ;;
  esac
  case ${e%%=*} in *[!A-Za-z0-9_]*) die "bad variable name in $e" ;; esac
  case ${e#*=} in *[!A-Za-z0-9_./:@+=,-]*) die "variable value for ${e%%=*} has a character outside the plain set" ;; esac
done
for p in "${props[@]+"${props[@]}"}"; do
  case $p in
    [A-Za-z]*=*) ;;
    *) die "--prop needs NAME=VALUE: $p" ;;
  esac
  case $p in *$'\n'*) die "--prop holds a newline" ;; esac
done
[ "$#" -ge 1 ] || die "no command after --"
case $1 in /*) ;; *) die "the command must be an absolute path" ;; esac

if [ -n "$netns" ] && [ -n "$nspath" ]; then die "--netns and --netns-path are exclusive"; fi
if [ "$hostnet" -eq 1 ] && { [ -n "$netns" ] || [ -n "$nspath" ]; }; then die "--host-network and a namespace are exclusive"; fi
if [ "$hostnet" -eq 0 ] && [ -z "$netns" ] && [ -z "$nspath" ]; then die "give --netns NAME or --host-network"; fi

log="$logdir/$name.log"
sysout="$logdir/$name.systemd"

# ---- the namespace ----
cmd=("$@")
if [ -n "$netns" ]; then
  valid_name "$netns" || die "--netns is not a plain name"
  nspath="/run/netns/$netns"
  [ -e "$nspath" ] || die "namespace $nspath does not exist"
  nsinode=$(sudo -n stat -L -c %i "$nspath") || die "cannot read the inode of $nspath"
elif [ -n "$nspath" ]; then
  valid_path "$nspath" || die "--netns-path is not plain"
  case $nsinode in '' | *[!0-9]*) die "--netns-path needs --netns-inode N" ;; esac
fi
if [ -n "$nspath" ]; then
  valid_path "$guard" || die "--guard must be a plain absolute path"
  cmd=("$guard" --netns-inode "$nsinode" -- "$@")
fi

# ---- the property list ----
P=()
P+=("User=$user" "Group=$group" "WorkingDirectory=$workdir" "UMask=0077")
P+=("Type=$type")
[ -z "$exit_type" ] || P+=("ExitType=$exit_type")
P+=("StandardInput=null" "StandardOutput=append:$log" "StandardError=inherit")
P+=("KillMode=control-group" "SendSIGKILL=yes" "TimeoutStopSec=15" "RuntimeMaxSec=$runtime_max" "LimitCORE=0")
P+=("NoNewPrivileges=yes" "CapabilityBoundingSet=" "AmbientCapabilities=" "RestrictSUIDSGID=yes" "LockPersonality=yes" "RestrictRealtime=yes")
P+=("SystemCallArchitectures=native" "SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register" "SystemCallErrorNumber=EPERM")
P+=("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK" "RestrictNamespaces=yes" "PrivateIPC=yes" "RemoveIPC=yes")
P+=("ProtectKernelModules=yes" "ProtectKernelTunables=yes" "ProtectKernelLogs=yes" "ProtectControlGroups=yes" "ProtectClock=yes" "ProtectHostname=yes")
P+=("ProtectProc=invisible")
P+=("ProtectSystem=strict" "ProtectHome=tmpfs" "PrivateDevices=yes")
if [ "$shm" = tmpfs ]; then
  P+=("TemporaryFileSystem=/run /var:ro /opt /mnt /media /srv /tmp:mode=1777 /dev/shm:mode=1777" "InaccessiblePaths=-/dev/mqueue")
else
  P+=("TemporaryFileSystem=/run /var:ro /opt /mnt /media /srv /tmp:mode=1777" "InaccessiblePaths=-/dev/mqueue -/dev/shm")
fi
if [ "${#binds[@]}" -gt 0 ]; then P+=("BindPaths=${binds[*]}"); fi
if [ "${#robinds[@]}" -gt 0 ]; then P+=("BindReadOnlyPaths=${robinds[*]}"); fi
if [ -n "$nspath" ]; then
  P+=("NetworkNamespacePath=$nspath" "IPAddressDeny=any" "IPAddressAllow=127.0.0.1/32 ::1/128")
fi
P+=("Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
for e in "${envs[@]+"${envs[@]}"}"; do P+=("Environment=$e"); done
for p in "${props[@]+"${props[@]}"}"; do P+=("$p"); done

# systemd expands $VAR in an ExecStart argument; double each dollar so that every argument
# reaches the program as written.
final=()
for a in "${cmd[@]}"; do final+=("${a//\$/\$\$}"); done

sdargs=("--unit=$name" "--collect" "--description=sandbox unit $name")
[ "$wait" -eq 0 ] || sdargs+=("--wait")
for p in "${P[@]}"; do sdargs+=("-p" "$p"); done
sdargs+=("--" "${final[@]}")

if [ "$dry" -eq 1 ]; then
  printf 'PROPERTY %s\n' "${P[@]}"
  printf 'COMMAND %s\n' "${final[@]}"
  exit 0
fi

# ---- start ----
# The files are made first, by the runner, with noclobber: a name that exists is refused. The
# manager opens the output file as root and follows links, so its folder must be one that no
# account can reach (checked by the caller's setup, and the unit's view hides it).
: >"$log" || die "cannot make $log (a unit of this name ran before?)"
: >"$sysout" || die "cannot make $sysout"

sudo -n systemd-run "${sdargs[@]}" >>"$sysout" 2>&1 </dev/null
rc=$?

# ---- replay, after the unit has ended ----
if [ "$wait" -eq 1 ]; then
  "$here/replay-log.sh" "$sysout" "$prefix.systemd"
  "$here/replay-log.sh" "$log" "$prefix"
  echo "run-unit: $name exit $rc"
else
  "$here/replay-log.sh" "$sysout" "$prefix.systemd"
  echo "run-unit: $name started, exit $rc"
fi
exit "$rc"
