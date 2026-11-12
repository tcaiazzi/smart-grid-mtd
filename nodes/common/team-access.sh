#!/bin/bash
# team-access.sh — how a team's people get onto a host, with what they type on
# record. One script, one subcommand per kind of access:
#
#   team-access.sh audit
#       record every interactive bash command on this host (command_audit.sh)
#   team-access.sh terminal PORT USER PASSWORD
#       audit, then serve a web terminal (ttyd) on PORT behind USER:PASSWORD;
#       every session is also transcribed whole to /var/log/terminal.typescript
#   team-access.sh jump NAME=IP...
#       make this host the one the team reaches the others from: an SSH key
#       pair of its own (the public key is printed) and the others by name
#   team-access.sh sshd LISTEN_IP PUBLIC_KEY
#       audit, then accept that key over SSH on LISTEN_IP only
#
# Copied flat onto the hosts a team works from, with command_audit.sh; needs
# ttyd and OpenSSH from the node image.
set -eu

audit() {
    grep -q command_audit /etc/bash.bashrc 2>/dev/null ||
        echo '[ -r /command_audit.sh ] && . /command_audit.sh' >>/etc/bash.bashrc
    touch /var/log/commands.jsonl
}

case "${1:-}" in
audit)
    audit
    ;;
terminal)
    port=$2 user=$3 password=$4
    audit
    # -W: writable (ttyd serves read-only otherwise). `script -a` appends each
    # session to one transcript; bash starts from "/", where the tools are staged.
    cd /
    touch /var/log/terminal.typescript
    exec ttyd -p "$port" -W -c "$user:$password" -t titleFixed="$user@$(hostname)" \
        script -qaf /var/log/terminal.typescript -c "bash"
    ;;
jump)
    shift
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    [ -f /root/.ssh/id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519
    for pair in "$@"; do
        grep -q " ${pair%%=*}\$" /etc/hosts || echo "${pair#*=} ${pair%%=*}" >>/etc/hosts
    done
    # The lab's hosts are new at every deploy: their keys are learned on first use.
    printf 'Host *\n    StrictHostKeyChecking accept-new\n    UserKnownHostsFile /root/.ssh/known_hosts\n' \
        >/root/.ssh/config
    cat /root/.ssh/id_ed25519.pub
    ;;
sshd)
    listen=$2 key=$3
    audit
    mkdir -p /root/.ssh /run/sshd
    chmod 700 /root/.ssh
    echo "$key" >/root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
    ssh-keygen -A >/dev/null
    # Key only, and only on the management address: the host's other networks
    # are where an attacker would be knocking from.
    exec /usr/sbin/sshd -D -e -o ListenAddress="$listen" -o PasswordAuthentication=no \
        -o PermitRootLogin=prohibit-password
    ;;
*)
    echo "usage: team-access.sh audit | terminal PORT USER PASSWORD | jump NAME=IP... | sshd IP KEY" >&2
    exit 2
    ;;
esac
