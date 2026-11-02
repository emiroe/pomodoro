#!/bin/bash
# CD (agent box, user timer pomodoro-deploy every 5 min). No GitHub remote yet: deploys the local main commit to the Docker host,
# health-checks it, rolls back to the previous commit on failure. State: ~/pomodoro/.deployed on the Docker host.
set -u
REPO=/home/crn/pomodoro; HOST=crn@192.168.1.50; LOG=/home/crn/pomodoro-deploy/deploy.log
log(){ echo "$(date '+%F %T') $*" | tee -a $LOG; }
cd $REPO || exit 1
HEAD=$(git rev-parse HEAD)
DEPLOYED=$(ssh $HOST 'cat ~/pomodoro/.deployed 2>/dev/null')
[ "$DEPLOYED" = "$HEAD" ] && exit 0
push(){ # $1 = commit
  T=$(mktemp -d); git archive "$1" | tar -x -C "$T" && rsync -a --delete --exclude .env --exclude .deployed --exclude .git "$T/" $HOST:pomodoro/; R=$?; rm -rf "$T"; return $R; }
up(){ ssh $HOST 'cd ~/pomodoro && docker compose up -d --build 2>&1 | tail -2' >>$LOG 2>&1
  for i in $(seq 1 20); do sleep 3; ssh $HOST 'curl -sf localhost:7360/health' >/dev/null && return 0; done; return 1; }
log "deploying ${HEAD:0:8} (was ${DEPLOYED:0:8})"
if push "$HEAD" && up; then ssh $HOST "echo $HEAD > ~/pomodoro/.deployed"; log "deployed ${HEAD:0:8}"; exit 0; fi
log "FAILED ${HEAD:0:8}: rolling back"
if [ -n "$DEPLOYED" ] && push "$DEPLOYED" && up; then log "rolled back to ${DEPLOYED:0:8}"; else log "ROLLBACK FAILED"; fi
~/ha-tools/venv/bin/python ~/ha-tools/ws.py "[{\"type\":\"call_service\",\"domain\":\"persistent_notification\",\"service\":\"create\",\"service_data\":{\"title\":\"Pomodoro deploy failed\",\"message\":\"Commit ${HEAD:0:8} failed its health check; rolled back. See ~/pomodoro-deploy/deploy.log on the agent box.\"}}]" >/dev/null 2>&1
exit 1
