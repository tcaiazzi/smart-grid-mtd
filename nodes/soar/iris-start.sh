#!/bin/bash
# iris-start.sh — start one DFIR-IRIS service on its cps-soc node, as IRIS's own
# compose file does (one container per service), with the lab's addresses in the
# place of the compose's service names.
#
#   iris-start.sh db | mq | app | worker | web
#
# Each service waits for the ones it needs, then runs its official entrypoint.
# The environment is IRIS's own (.env of its compose file): the cps-soc
# scenario sets it per run, with fresh secrets.
#
# Copied flat onto every IRIS node; needs bash (all of IRIS's images have it).
set -eu

# Until a TCP port answers: compose's depends_on, without compose.
wait_for() {
    until (echo > "/dev/tcp/$1/$2") 2>/dev/null; do sleep 1; done
}

case "${1:?usage: iris-start.sh db|mq|app|worker|web}" in
    db) exec docker-entrypoint.sh postgres ;;
    mq) exec docker-entrypoint.sh rabbitmq-server ;;
    app)
        wait_for "${POSTGRES_SERVER:?}" "${POSTGRES_PORT:-5432}"
        wait_for "${CELERY_BROKER#amqp://}" 5672
        cd /iriswebapp
        exec ./iris-entrypoint.sh iriswebapp
        ;;
    worker)
        cd /iriswebapp
        exec ./wait-for-iriswebapp.sh "${IRIS_UPSTREAM_SERVER:?}:${IRIS_UPSTREAM_PORT:-8000}" \
            ./iris-entrypoint.sh iris-worker
        ;;
    # The node runs as root, which Kathará needs to address it; nginx runs as
    # www-data, as in IRIS's own image. It logs to /dev/stdout and /dev/stderr,
    # which it reopens as www-data: the console log they lead to, created by
    # root, has to be www-data's too, or nginx cannot start.
    web)
        for fd in 1 2; do
            out=$(readlink -f "/proc/self/fd/$fd")
            if [ -f "$out" ]; then chown www-data "$out"; fi
        done
        exec runuser -u www-data -- /entrypoint.sh
        ;;
    *) echo "unknown IRIS service: $1" >&2; exit 2 ;;
esac
