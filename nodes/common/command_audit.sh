# command_audit.sh — record every command typed in an interactive bash.
#
# Sourced from /etc/bash.bashrc (team-access.sh installs it), so it holds for a
# web terminal and for an SSH session alike. One JSON line per command goes to
# $AUDIT_LOG when the command starts, so one that never returns (an ssh to
# another host, a hung tool) is on record too; a second line carries its exit
# code when the prompt comes back.
#
# It is a record, not a control: root on the node can switch it off. The
# terminal's own transcript (team-access.sh, `script`) shows that as well.

AUDIT_LOG=${AUDIT_LOG:-/var/log/commands.jsonl}

__audit_json() {
    # A string as the inside of a JSON string.
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

__audit_ancestry() {
    # Where this shell comes from, as JSON fields: the processes above it,
    # nearest first, and whether the chain ends at init. Two words per process
    # name a service (python3 vuln_app.py, ttyd -p) and stop short of a secret
    # passed further along its command line. A shell opened from outside the
    # container (docker exec) has no init above it; one that a service left
    # behind as an orphan does.
    local pid=$PPID next top=$$ out="" n=0 key value
    local -a argv
    while [ "${pid:-0}" -gt 0 ] && [ "$n" -lt 32 ]; do
        argv=()
        mapfile -d '' -t argv <"/proc/$pid/cmdline" 2>/dev/null
        out+="${out:+, }\"$(__audit_json "${argv[0]:-?}${argv[1]:+ ${argv[1]}}")\""
        top=$pid next=""
        while read -r key value _; do
            [ "$key" = PPid: ] && next=$value
        done <"/proc/$pid/status" 2>/dev/null
        pid=$next n=$((n + 1))
    done
    printf '"ancestry": [%s], "orphan": %s' "$out" "$([ "$top" = 1 ] && echo true || echo false)"
}
__audit_origin=$(__audit_ancestry)  # once: a shell's ancestors do not change under it

__audit_row() {
    # __audit_row KIND EXTRA_JSON_FIELDS
    local line
    line=$(HISTTIMEFORMAT='' history 1)
    line=${line#"${line%%[![:space:]]*}"}
    local n=${line%%[![:digit:]]*}
    local cmd=${line#"$n"}
    cmd=${cmd#"${cmd%%[![:space:]]*}"}
    printf '{"t": %s, "kind": "%s", "n": %s, "host": "%s", "user": "%s", "tty": "%s", "from": "%s", "cwd": "%s", "cmd": "%s", %s%s}\n' \
        "$(date +%s.%3N)" "$1" "${n:-0}" "$(__audit_json "${HOSTNAME:-}")" \
        "$(__audit_json "${USER:-$(id -un)}")" "$(__audit_json "$(tty 2>/dev/null)")" \
        "${SSH_CONNECTION%% *}" "$(__audit_json "$PWD")" "$(__audit_json "$cmd")" \
        "$__audit_origin" "$2" \
        >>"$AUDIT_LOG" 2>/dev/null
}

__audit_done() {
    local rc=$?
    # PS0 ran for a command since the last prompt: only then is there one to close.
    if [ -e "$__audit_mark" ]; then
        rm -f "$__audit_mark"
        __audit_row command_end ", \"rc\": $rc"
    fi
    return $rc
}

# PS0 is expanded once per command, after it is read and before it runs; an
# empty line expands nothing. It runs in a subshell, hence the mark on disk.
__audit_mark=/tmp/.audit.$$
PS0='$(__audit_row command ""; : >"$__audit_mark")'
PROMPT_COMMAND="__audit_done${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
