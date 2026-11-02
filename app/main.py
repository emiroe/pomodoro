import asyncio, secrets, urllib.parse, os, hmac, hashlib, time, datetime, csv, io
from zoneinfo import ZoneInfo
from contextlib import asynccontextmanager
from psycopg_pool import ConnectionPool
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

DB = os.environ["DATABASE_URL"]
PASSWORD = os.environ.get("EDIT_PASSWORD", "")
SECRET = os.environ["SECRET_KEY"].encode()
TZ = ZoneInfo("Europe/Amsterdam")
pool = ConnectionPool(DB, min_size=1, max_size=5, open=False)

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (id serial PRIMARY KEY, day date NOT NULL, seconds int NOT NULL CHECK (seconds > 0 AND seconds <= 86400),
  project text NOT NULL DEFAULT '', note text NOT NULL DEFAULT '', pomodoro boolean NOT NULL DEFAULT false, updated_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS client_id text;   -- id given by the offline menu bar plugin, makes its upload idempotent
CREATE UNIQUE INDEX IF NOT EXISTS sessions_client_id ON sessions(client_id) WHERE client_id IS NOT NULL;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ended_at timestamptz;   -- set for timer sessions (start = ended_at - seconds); NULL for manual/Reset Day ones
CREATE INDEX IF NOT EXISTS sessions_day ON sessions(day);
CREATE TABLE IF NOT EXISTS todos (id serial PRIMARY KEY, text text NOT NULL, done boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE todos ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'todo';
UPDATE todos SET status='finished' WHERE done AND status='todo';   -- before the tabs existed 'done' was the only state
CREATE TABLE IF NOT EXISTS projects (name text PRIMARY KEY, color text NOT NULL DEFAULT '#7c9cff', position serial);
CREATE TABLE IF NOT EXISTS settings (key text PRIMARY KEY, value text NOT NULL);
INSERT INTO settings VALUES ('focus_min','25'),('short_min','5'),('long_min','15'),('long_every','4'),('daily_goal','8') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS timer (id int PRIMARY KEY DEFAULT 1 CHECK (id = 1), phase text NOT NULL DEFAULT 'focus', dur_ms bigint NOT NULL,
  acc_ms bigint NOT NULL DEFAULT 0, start_ms bigint NOT NULL DEFAULT 0, project text NOT NULL DEFAULT '', note text NOT NULL DEFAULT '', cycle int NOT NULL DEFAULT 0);
ALTER TABLE timer ADD COLUMN IF NOT EXISTS day date;
"""
LIMITS = {"focus_min": (1, 180), "short_min": (1, 60), "long_min": (1, 120), "long_every": (2, 12), "daily_goal": (1, 40)}

@asynccontextmanager
async def lifespan(app):
    pool.open(wait=True)
    with pool.connection() as c: c.execute(SCHEMA)
    task = asyncio.create_task(ticker())
    yield
    task.cancel()
    pool.close()

app = FastAPI(lifespan=lifespan)

# Password: starts as EDIT_PASSWORD from .env; once changed in the app a scrypt hash lives in settings.pw_hash and wins.
# settings.pw_ver is mixed into the cookie signature, so changing the password signs every other device out.
# Forgot it? DELETE FROM settings WHERE key IN ('pw_hash','pw_ver')  -> the .env password works again.
def pw_state():
    with pool.connection() as c: return dict(c.execute("SELECT key,value FROM settings WHERE key IN ('pw_hash','pw_ver')").fetchall())
def hash_pw(pw, salt=None):
    salt = salt or os.urandom(16).hex()
    return salt + "$" + hashlib.scrypt(pw.encode(), salt=salt.encode(), n=2**14, r=8, p=1).hex()
def pw_ok(pw, st=None):
    st = pw_state() if st is None else st
    if "pw_hash" in st:
        salt, _ = st["pw_hash"].split("$")
        return hmac.compare_digest(hash_pw(pw, salt), st["pw_hash"])
    return bool(PASSWORD) and hmac.compare_digest(pw, PASSWORD)
def sign(ts, ver=None):
    ver = pw_state().get("pw_ver", "") if ver is None else ver
    return hmac.new(SECRET + ver.encode(), str(ts).encode(), hashlib.sha256).hexdigest()
def authed(req: Request):
    try: ts, sig = req.cookies.get("pm_auth", "").split(".")
    except ValueError: return False
    return hmac.compare_digest(sig, sign(ts)) and time.time() - int(ts) < 90 * 86400
def need_auth(req):
    if not authed(req): raise HTTPException(401, "login required")
def need_timer(req):
    # the timer endpoints also accept the menu bar plugin's key (header X-Timer-Key); it can do nothing else (no sessions, no settings, no Reset Day)
    if authed(req): return
    k = req.headers.get("x-timer-key", "")
    with pool.connection() as c: r = c.execute("SELECT value FROM settings WHERE key='timer_key_hash'").fetchone()
    if k and r and hmac.compare_digest(hashlib.sha256(k.encode()).hexdigest(), r[0]): return
    raise HTTPException(401, "login required")
def today(): return datetime.datetime.now(TZ).date()

class Login(BaseModel): password: str
class Session(BaseModel):
    id: int | None = None
    day: str; seconds: int; project: str = ""; note: str = ""
class Project(BaseModel):
    name: str; color: str = "#7c9cff"
class Settings(BaseModel):
    focus_min: int | None = None; short_min: int | None = None; long_min: int | None = None; long_every: int | None = None; daily_goal: int | None = None

@app.post("/api/login")
def login(b: Login, resp: Response):
    if not pw_ok(b.password): raise HTTPException(403, "wrong password")
    ts = int(time.time())
    resp.set_cookie("pm_auth", "%d.%s" % (ts, sign(ts)), max_age=90 * 86400, httponly=True, samesite="lax", secure=True)
    return {"ok": True}

class NewPassword(BaseModel): current: str; new: str

@app.post("/api/password")
def change_password(b: NewPassword, req: Request, resp: Response):
    need_auth(req)
    st = pw_state()
    if not pw_ok(b.current, st): raise HTTPException(403, "current password is wrong")
    if len(b.new) < 8: raise HTTPException(400, "new password needs at least 8 characters")
    ver = str(int(st.get("pw_ver", "0")) + 1)
    with pool.connection() as c:
        for k, v in (("pw_hash", hash_pw(b.new)), ("pw_ver", ver)):
            c.execute("INSERT INTO settings VALUES (%s,%s) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value", (k, v))
    ts = int(time.time())   # keep this device signed in, every other one has to log in again
    resp.set_cookie("pm_auth", "%d.%s" % (ts, sign(ts, ver)), max_age=90 * 86400, httponly=True, samesite="lax", secure=True)
    return {"ok": True}

@app.post("/api/logout")
def logout(resp: Response):
    resp.delete_cookie("pm_auth"); return {"ok": True}

def hhmm(t): return t.astimezone(TZ).strftime("%H:%M")
def srow(r):
    return {"id": r[0], "day": r[1].isoformat(), "seconds": r[2], "project": r[3], "note": r[4], "pomodoro": r[5],
            "start": hhmm(r[6] - datetime.timedelta(seconds=r[2])) if r[6] else None, "end": hhmm(r[6]) if r[6] else None}
def get_settings(c): return {k: int(v) for k, v in c.execute("SELECT key,value FROM settings WHERE key = ANY(%s)", (list(LIMITS),)).fetchall()}

@app.get("/api/state")
def state(req: Request):
    with pool.connection() as c:
        rows = c.execute("SELECT id,day,seconds,project,note,pomodoro,ended_at FROM sessions ORDER BY day DESC, ended_at DESC NULLS LAST, id DESC").fetchall()
        projects = [{"name": r[0], "color": r[1]} for r in c.execute("SELECT name,color FROM projects ORDER BY position").fetchall()]
        st = get_settings(c)
        todos = todo_list(c) if authed(req) else []      # the to-do list is private: only shown when logged in
    return {"edit": authed(req), "sessions": [srow(r) for r in rows], "projects": projects, "settings": st, "today": today().isoformat(), "todos": todos}

TODO_STATUS = ("todo", "hold", "review", "finished")

def todo_list(c):
    return [{"id": r[0], "text": r[1], "status": r[2]} for r in c.execute("SELECT id,text,status FROM todos ORDER BY id").fetchall()]

class Todo(BaseModel): text: str | None = None; status: str | None = None

@app.post("/api/todo")
def todo_add(b: Todo, req: Request):
    need_auth(req)
    text = (b.text or "").strip()[:200]; status = b.status or "todo"
    if not text or status not in TODO_STATUS: raise HTTPException(400, "bad to-do")
    with pool.connection() as c:
        c.execute("INSERT INTO todos(text,status,done) VALUES (%s,%s,%s)", (text, status, status == "finished")); return {"todos": todo_list(c)}

@app.post("/api/todo/{tid}")
def todo_update(tid: int, b: Todo, req: Request):
    need_auth(req)
    if b.status is not None and b.status not in TODO_STATUS: raise HTTPException(400, "bad status")
    with pool.connection() as c:
        if b.status is not None: c.execute("UPDATE todos SET status=%s, done=%s WHERE id=%s", (b.status, b.status == "finished", tid))
        if b.text is not None and b.text.strip(): c.execute("UPDATE todos SET text=%s WHERE id=%s", (b.text.strip()[:200], tid))
        return {"todos": todo_list(c)}

@app.delete("/api/todo/{tid}")
def todo_delete(tid: int, req: Request):
    need_auth(req)
    with pool.connection() as c:
        c.execute("DELETE FROM todos WHERE id=%s", (tid,)); return {"todos": todo_list(c)}

@app.delete("/api/todos/done")
def todo_clear_done(req: Request):
    need_auth(req)   # clears the Finished tab
    with pool.connection() as c:
        c.execute("DELETE FROM todos WHERE status='finished'"); return {"todos": todo_list(c)}

def check(b: Session):
    try: datetime.date.fromisoformat(b.day)
    except ValueError: raise HTTPException(400, "bad date")
    if not 1 <= b.seconds <= 86400: raise HTTPException(400, "time must be between 1 second and 24 hours")

def ensure_project(c, name):
    name = name.strip()[:60]
    if name: c.execute("INSERT INTO projects(name) VALUES (%s) ON CONFLICT DO NOTHING", (name,))
    return name

@app.post("/api/session")
def save(b: Session, req: Request):
    need_auth(req); check(b)
    with pool.connection() as c:
        p = ensure_project(c, b.project)
        if b.id:
            r = c.execute("UPDATE sessions SET day=%s,seconds=%s,project=%s,note=%s,updated_at=now() WHERE id=%s RETURNING id",
                          (b.day, b.seconds, p, b.note[:300], b.id)).fetchone()
            if not r: raise HTTPException(404, "no such session")
        else:
            r = c.execute("INSERT INTO sessions(day,seconds,project,note) VALUES (%s,%s,%s,%s) RETURNING id", (b.day, b.seconds, p, b.note[:300])).fetchone()
    return {"ok": True, "id": r[0]}

@app.delete("/api/session/{sid}")
def delete(sid: int, req: Request):
    need_auth(req)
    with pool.connection() as c: c.execute("DELETE FROM sessions WHERE id=%s", (sid,))
    return {"ok": True}

@app.post("/api/project")
def project_save(b: Project, req: Request):
    need_auth(req)
    name = b.name.strip()[:60]
    if not name or not (len(b.color) == 7 and b.color[0] == "#"): raise HTTPException(400, "bad project")
    with pool.connection() as c:
        c.execute("INSERT INTO projects(name,color) VALUES (%s,%s) ON CONFLICT (name) DO UPDATE SET color=EXCLUDED.color", (name, b.color))
    return {"ok": True}

@app.delete("/api/project/{name}")
def project_delete(name: str, req: Request):
    need_auth(req)   # sessions keep their project name; it just stops being a pick-list entry
    with pool.connection() as c: c.execute("DELETE FROM projects WHERE name=%s", (name,))
    return {"ok": True}

@app.post("/api/settings")
def settings(b: Settings, req: Request):
    need_auth(req)
    with pool.connection() as c:
        for k, v in b.model_dump().items():
            if v is None: continue
            lo, hi = LIMITS[k]
            if not lo <= v <= hi: raise HTTPException(400, "bad value for " + k)
            c.execute("UPDATE settings SET value=%s WHERE key=%s", (str(v), k))
    return {"ok": True}

# One timer for all devices, kept on the SERVER clock (clients only show the difference, so device clocks do not matter).
# remaining = dur_ms - (acc_ms + (now - start_ms if running)); start_ms = 0 while paused. A finished focus block is logged by
# /api/timer/complete (any client calls it when the countdown hits 0 or on opening the page); it is idempotent.
def now_ms(): return int(time.time() * 1000)
def phase_ms(st, phase): return st[{"focus": "focus_min", "short": "short_min", "long": "long_min"}[phase]] * 60000
def timer_state(c):
    r = c.execute("SELECT phase,dur_ms,acc_ms,start_ms,project,note,cycle FROM timer WHERE id=1").fetchone()
    if r is None:
        st = get_settings(c)
        c.execute("INSERT INTO timer(id,phase,dur_ms) VALUES (1,'focus',%s)", (phase_ms(st, "focus"),))
        r = ("focus", phase_ms(st, "focus"), 0, 0, "", "", 0)
    return {"timer": {"phase": r[0], "dur": r[1], "acc": r[2], "start": r[3], "project": r[4], "note": r[5], "cycle": r[6]}, "now": now_ms()}

def next_phase(c, phase, cycle):
    st = get_settings(c)
    if phase != "focus": return "focus", cycle
    cycle += 1
    return ("long" if cycle % st["long_every"] == 0 else "short"), cycle

def move_on(c, log_seconds, end_ms):
    """Close the current block (optionally logging log_seconds as a pomodoro ending at end_ms) and park the next one, paused."""
    r = c.execute("SELECT phase,project,note,cycle FROM timer WHERE id=1 FOR UPDATE").fetchone()
    phase, project, note, cycle = r
    if phase == "focus" and log_seconds > 0:
        day = datetime.datetime.fromtimestamp(end_ms / 1000, TZ).date()
        c.execute("INSERT INTO sessions(day,seconds,project,note,pomodoro,ended_at) VALUES (%s,%s,%s,%s,true,to_timestamp(%s))", (day, min(86400, log_seconds), project, note, end_ms / 1000))
    nxt, cycle = next_phase(c, phase, cycle) if (phase != "focus" or log_seconds > 0) else (phase, cycle)
    c.execute("UPDATE timer SET phase=%s,dur_ms=%s,acc_ms=0,start_ms=0,cycle=%s,day=NULL WHERE id=1", (nxt, phase_ms(get_settings(c), nxt), cycle))

class TimerStart(BaseModel): project: str | None = None; note: str | None = None
@app.get("/api/timer")
def timer_get(req: Request):
    need_timer(req)
    with pool.connection() as c: return timer_state(c)

@app.post("/api/timer/start")
def timer_start(b: TimerStart, req: Request):
    need_timer(req)
    with pool.connection() as c:
        timer_state(c)
        if b.project is not None: c.execute("UPDATE timer SET project=%s WHERE id=1", (ensure_project(c, b.project),))
        if b.note is not None: c.execute("UPDATE timer SET note=%s WHERE id=1", (b.note[:300],))   # note=None (menu bar 'Start as…') keeps the note typed in the app
        c.execute("UPDATE timer SET start_ms=%s, day=COALESCE(day,%s) WHERE id=1 AND start_ms=0", (now_ms(), today()))
        return timer_state(c)

@app.post("/api/timer/startp")
def timer_startp(project: str, req: Request):
    return timer_start(TimerStart(project=project), req)

@app.post("/api/timer/pause")
def timer_pause(req: Request):
    need_timer(req)
    with pool.connection() as c:
        timer_state(c)
        c.execute("UPDATE timer SET acc_ms=acc_ms+%s-start_ms, start_ms=0 WHERE id=1 AND start_ms<>0", (now_ms(),))
        return timer_state(c)

@app.post("/api/timer/label")
def timer_label(b: TimerStart, req: Request):
    need_auth(req)
    with pool.connection() as c:
        timer_state(c)
        c.execute("UPDATE timer SET project=%s,note=%s WHERE id=1", (ensure_project(c, b.project or ""), (b.note or "")[:300]))
        return timer_state(c)

def complete_if_due(c):
    # acts only when the countdown really reached 0 on the server clock; the block is logged with the moment it ended
    s = timer_state(c)["timer"]
    if not s["start"]: return
    el = s["acc"] + now_ms() - s["start"]
    if el >= s["dur"]:
        move_on(c, s["dur"] // 1000, s["start"] + (s["dur"] - s["acc"]))
        # natural end of a block = an 'event' the menu bar plugin turns into a notification (skip / log now / reset are not events)
        n = int(c.execute("SELECT value FROM settings WHERE key='ev_id'").fetchone()[0]) + 1 if c.execute("SELECT 1 FROM settings WHERE key='ev_id'").fetchone() else 1
        for k, v in (("ev_id", str(n)), ("ev_kind", "focus" if s["phase"] == "focus" else "break"), ("ev_at", str(now_ms()))):
            c.execute("INSERT INTO settings VALUES (%s,%s) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value", (k, v))

async def ticker():
    # the server itself closes finished blocks (no browser needs to be open)
    while True:
        await asyncio.sleep(5)
        try: await asyncio.to_thread(tick)
        except Exception as e: print("ticker:", e)

def tick():
    with pool.connection() as c: complete_if_due(c)

@app.post("/api/timer/complete")
def timer_complete(req: Request):
    need_timer(req)
    with pool.connection() as c:
        complete_if_due(c)
        return timer_state(c)

@app.post("/api/timer/finish")
def timer_finish(req: Request):
    # 'Log it now': stop a focus block early and log the time done so far (needs at least 1 minute)
    need_timer(req)
    with pool.connection() as c:
        s = timer_state(c)["timer"]
        el = s["acc"] + (now_ms() - s["start"] if s["start"] else 0)
        if s["phase"] != "focus" or el < 60000: raise HTTPException(400, "nothing to log yet")
        move_on(c, el // 1000, now_ms())
        return timer_state(c)

@app.post("/api/timer/skip")
def timer_skip(req: Request):
    # skip a break (or drop a focus block without logging it)
    need_timer(req)
    with pool.connection() as c:
        s = timer_state(c)["timer"]
        if s["phase"] == "focus":
            c.execute("UPDATE timer SET acc_ms=0,start_ms=0,day=NULL WHERE id=1")
        else: move_on(c, 0, now_ms())
        return timer_state(c)

@app.delete("/api/timer")
def timer_reset(req: Request):
    # 'Reset Day': time already done on an unfinished focus block (>= 1 min) is logged first, under the day the block was started
    # (so a reset the next morning books it on the previous day), with the timer's project and note; it is time, not a pomodoro.
    need_auth(req)
    with pool.connection() as c:
        logged = 0
        r = c.execute("SELECT phase,acc_ms,start_ms,project,note,day FROM timer WHERE id=1").fetchone()
        if r is not None and r[0] == "focus":
            el = r[1] + (now_ms() - r[2] if r[2] else 0)
            if el >= 60000:
                logged = min(86400, el // 1000)
                c.execute("INSERT INTO sessions(day,seconds,project,note,pomodoro) VALUES (%s,%s,%s,%s,false)", (r[5] or today(), logged, r[3], r[4]))
        c.execute("DELETE FROM timer WHERE id=1")
        return dict(timer_state(c), logged=logged)

# ---- menu bar plugin (SwiftBar / xbar on the Mac): the page downloads a tiny script holding a timer-only key; the server renders the menu.
PLUGIN = r"""#!/bin/bash
# <swiftbar.title>Pomodoro</swiftbar.title><xbar.title>Pomodoro</xbar.title>
# Pomodoro timer in the menu bar. Refreshes every second (name: pomodoro.1s.sh). The key can only control the timer and upload finished
# pomodoros; revoke it in Pomodoro > Settings. Notification + sound when a pomodoro or break ends.
# OFFLINE: when the site cannot be reached (e.g. at the office) this script runs its own timer, keeps every finished pomodoro in a queue
# on this Mac and uploads the queue by itself as soon as the site is reachable again. Data: ~/Library/Application Support/pomodoro-offline
URL="@BASE@"; KEY="@SECRET@"; SELF="$0"
D="$HOME/Library/Application Support/pomodoro-offline"; mkdir -p "$D"
STATE="$D/state"; QUEUE="$D/queue"; CONF="$D/config"; PROJ="$D/projects"; EVF="$HOME/Library/Caches/pomodoro-plugin.event"
NOW=$(date +%s)
notify(){ osascript -e "display notification \"$1\" with title \"Pomodoro\" sound name \"Glass\"" >/dev/null 2>&1 & }
clean(){ printf '%s' "$1" | tr -d "\"'\\\\\`\$\t\r\n" | cut -c1-60; }
FOCUS=25; SHORT=5; LONG=15; EVERY=4
[ -f "$CONF" ] && IFS=: read FOCUS SHORT LONG EVERY < "$CONF"
PHASE=focus; DUR=0; ACC=0; START=0; PROJECT=""; CYCLE=0
[ -f "$STATE" ] && . "$STATE"
save(){ printf "PHASE=%s\nDUR=%s\nACC=%s\nSTART=%s\nPROJECT='%s'\nCYCLE=%s\n" "$PHASE" "$DUR" "$ACC" "$START" "$PROJECT" "$CYCLE" > "$STATE"; }
phase_secs(){ case "$1" in focus) echo $((FOCUS*60));; short) echo $((SHORT*60));; *) echo $((LONG*60));; esac; }
[ "$DUR" -gt 0 ] 2>/dev/null || DUR=$(phase_secs "$PHASE")
active(){ [ -f "$STATE" ] && { [ "$START" -gt 0 ] || [ "$ACC" -gt 0 ]; }; }

# ---- actions of the offline menu (this script calls itself)
case "$1" in
  startas) PROJECT=$(clean "$2"); START=0; shift; set -- start;;
esac
case "$1" in
  start)  [ "$START" -eq 0 ] && START=$NOW; save; exit 0;;
  pause)  [ "$START" -gt 0 ] && { ACC=$((ACC + NOW - START)); START=0; save; }; exit 0;;
  skip)   if [ "$PHASE" = focus ]; then ACC=0; START=0; else PHASE=focus; ACC=0; START=0; DUR=$((FOCUS*60)); fi; save; exit 0;;
  reset)  rm -f "$STATE"; exit 0;;
esac

# ---- upload the queue (only while nothing else is uploading)
flush(){
  [ -s "$QUEUE" ] || return 0
  mkdir "$D/lock" 2>/dev/null || return 0
  mv "$QUEUE" "$QUEUE.sending"
  JSON=$(awk -F'\t' 'BEGIN{printf "{\"sessions\":["} {printf "%s{\"id\":\"%s\",\"end\":%s,\"seconds\":%s,\"project\":\"%s\"}", (NR>1?",":""), $4, $1, $2, $3} END{printf "]}"}' "$QUEUE.sending")
  if curl -fsS -m 15 -X POST -H "X-Timer-Key: $KEY" -H "Content-Type: application/json" -d "$JSON" "$URL/api/timer/offline" >/dev/null 2>&1; then rm -f "$QUEUE.sending"
  else cat "$QUEUE.sending" >> "$QUEUE"; rm -f "$QUEUE.sending"; fi
  rmdir "$D/lock"
}
queued(){ [ -s "$QUEUE" ] && wc -l < "$QUEUE" | tr -d ' ' || echo 0; }

# ---- offline timer
offline_menu(){
  if [ "$START" -gt 0 ] && [ $((ACC + NOW - START)) -ge "$DUR" ]; then   # a block ended by itself
    END=$((START + DUR - ACC))
    if [ "$PHASE" = focus ]; then
      printf '%s\t%s\t%s\t%s\n' "$END" "$DUR" "$PROJECT" "$END-$DUR" >> "$QUEUE"; CYCLE=$((CYCLE+1))
      if [ $((CYCLE % EVERY)) -eq 0 ]; then PHASE=long; else PHASE=short; fi; MSG="Pomodoro done. Time for a break."
    else PHASE=focus; MSG="Break over. Back to work."; fi
    DUR=$(phase_secs "$PHASE"); ACC=0; START=0; save
    [ $((NOW - END)) -lt 120 ] && notify "$MSG"
  fi
  EL=$ACC; [ "$START" -gt 0 ] && EL=$((ACC + NOW - START)); REM=$((DUR - EL)); [ "$REM" -lt 0 ] && REM=0
  CLK=$(printf '%02d:%02d' $((REM/60)) $((REM%60)))
  if [ "$PHASE" = focus ]; then ICON="🍅"; else ICON="☕"; fi; [ "$START" -eq 0 ] && [ "$ACC" -gt 0 ] && ICON="⏸"
  echo "📴 $ICON $CLK"; echo "---"
  echo "Offline: timer runs on this Mac, uploads when the site is reachable"
  [ "$PHASE" = focus ] && [ -n "$PROJECT" ] && echo "Focus · $PROJECT"
  A="terminal=false refresh=true"
  if [ "$START" -gt 0 ]; then echo "Pause | bash=\"$SELF\" param1=pause $A"
  else echo "$([ "$ACC" -gt 0 ] && echo Resume || echo Start) | bash=\"$SELF\" param1=start $A"; fi
  if [ "$PHASE" = focus ]; then [ "$ACC" -gt 0 ] || [ "$START" -gt 0 ] && echo "Reset Pomodoro | bash=\"$SELF\" param1=skip $A"
  else echo "Skip break | bash=\"$SELF\" param1=skip $A"; fi
  if [ "$PHASE" = focus ] && [ "$ACC" -eq 0 ] && [ "$START" -eq 0 ] && [ -s "$PROJ" ]; then
    echo "Start as…"
    tr ',' '\n' < "$PROJ" | while read -r P; do N=$(printf '%b' "${P//%/\\x}"); echo "--$(clean "$N") | bash=\"$SELF\" param1=startas param2=\"$(clean "$N")\" $A"; done
  fi
  echo "---"; echo "Waiting to upload: $(queued) pomodoro(s)"
}

# ---- an unfinished local block keeps running locally until it is done (so nothing is lost when the site comes back mid-block)
if active; then flush; offline_menu; exit 0; fi

HDR=$(mktemp)
if BODY=$(curl -fsS -m 3 -D "$HDR" -H "X-Timer-Key: $KEY" "$URL/api/menubar" 2>/dev/null); then
  hv(){ tr -d '\r' < "$HDR" | awk -F': ' -v k="$1" 'tolower($1)==k{print $2}'; }
  EV=$(hv x-pomodoro-event); C=$(hv x-pomodoro-config); P=$(hv x-pomodoro-projects); rm -f "$HDR"
  [ -n "$C" ] && echo "$C" > "$CONF"; [ -n "$P" ] && echo "$P" > "$PROJ"
  printf '%s\n' "$BODY" | sed "s|@URL@|$URL|g;s|@KEY@|$KEY|g"
  [ -s "$QUEUE" ] && flush
  [ -f "$STATE" ] && rm -f "$STATE"
  ID=${EV%%:*}; REST=${EV#*:}; KIND=${REST%%:*}; AGE=${REST#*:}; LAST=$(cat "$EVF" 2>/dev/null)
  if [ -n "$ID" ] && [ "$ID" != "$LAST" ]; then
    echo "$ID" > "$EVF"
    # first run only remembers the id; events older than 2 minutes (Mac was asleep) are not announced
    if [ -n "$LAST" ] && [ "${AGE:-999}" -lt 120 ]; then
      if [ "$KIND" = "focus" ]; then notify "Pomodoro done. Time for a break."; else notify "Break over. Back to work."; fi
    fi
  fi
else rm -f "$HDR"; offline_menu; fi
"""
@app.post("/api/menubar/key")
def menubar_key(req: Request):
    need_auth(req)   # a new key replaces (revokes) the old one
    key = secrets.token_hex(24)
    with pool.connection() as c:
        c.execute("INSERT INTO settings VALUES ('timer_key_hash',%s) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value", (hashlib.sha256(key.encode()).hexdigest(),))
    body = PLUGIN.replace("@BASE@", str(req.base_url).rstrip("/")).replace("@SECRET@", key)
    return PlainTextResponse(body, headers={"Content-Disposition": "attachment; filename=pomodoro.1s.sh"})

def menu_action(label, path, extra=""):
    return f"{label} | bash=/usr/bin/curl param1=-fsS param2=-X param3=POST param4=-H param5=X-Timer-Key:@KEY@ param6=@URL@{path} terminal=false refresh=true{extra}"

class OfflineSession(BaseModel): id: str; end: int; seconds: int; project: str = ""
class OfflineBatch(BaseModel): sessions: list[OfflineSession]

@app.post("/api/timer/offline")
def timer_offline(b: OfflineBatch, req: Request):
    # pomodoros the menu bar plugin finished while it could not reach the site; uploading the same id twice adds nothing
    need_timer(req)
    added = skipped = 0; t = time.time()
    with pool.connection() as c:
        for x in b.sessions[:500]:
            if not x.id or len(x.id) > 80 or not 1 <= x.seconds <= 86400 or not t - 45 * 86400 <= x.end <= t + 120: skipped += 1; continue
            end = datetime.datetime.fromtimestamp(x.end, TZ)
            r = c.execute("INSERT INTO sessions(day,seconds,project,pomodoro,ended_at,client_id) VALUES (%s,%s,%s,true,%s,%s) ON CONFLICT (client_id) WHERE client_id IS NOT NULL DO NOTHING RETURNING id",
                          (end.date(), x.seconds, ensure_project(c, x.project), end, x.id)).fetchone()
            added += 1 if r else 0
    return {"added": added, "skipped": skipped}

@app.get("/api/menubar")
def menubar(req: Request):
    need_timer(req)
    with pool.connection() as c:
        complete_if_due(c)
        t = timer_state(c); s = t["timer"]; now = t["now"]; st = get_settings(c)
        projects = [r[0] for r in c.execute("SELECT name FROM projects ORDER BY position").fetchall()]
        tp, ts = c.execute("SELECT count(*) FILTER (WHERE pomodoro), coalesce(sum(seconds),0) FROM sessions WHERE day=%s", (today(),)).fetchone()
    rem = max(0, s["dur"] - (s["acc"] + (now - s["start"] if s["start"] else 0)))
    sec = -(-rem // 1000); clock = "%02d:%02d" % (sec // 60, sec % 60)
    brk = s["phase"] != "focus"; running = bool(s["start"]); started = running or s["acc"] > 0
    icon = ("☕" if brk else "🍅") if running or not started else "⏸"
    L = [f"{icon} {clock}", "---", ("Break" if s["phase"] == "short" else "Long break" if s["phase"] == "long" else "Focus") + (f" · {s['project']}" if s["project"] and not brk else "")]
    L.append(menu_action("Pause", "/api/timer/pause") if running else menu_action("Resume" if started else "Start", "/api/timer/start"))
    if not brk and started and s["acc"] + (now - s["start"] if s["start"] else 0) >= 60000: L.append(menu_action("Log now", "/api/timer/finish"))
    if brk: L.append(menu_action("Skip break", "/api/timer/skip"))
    elif started: L.append(menu_action("Reset Pomodoro", "/api/timer/skip"))
    if projects and not started and not brk:
        L.append("Start as…")
        for n in projects: L.append("--" + menu_action(n.replace("|", "/"), "/api/timer/startp?project=" + urllib.parse.quote(n, safe="")))
    L += ["---", f"Today: {tp} / {st['daily_goal']} pomodoros · {ts // 3600}:{ts // 60 % 60:02d} worked", "Open Pomodoro | href=@URL@"]
    with pool.connection() as c: ev = dict(c.execute("SELECT key,value FROM settings WHERE key IN ('ev_id','ev_kind','ev_at')").fetchall())
    age = max(0, (now - int(ev.get("ev_at", 0))) // 1000) if ev else 0
    return PlainTextResponse("\n".join(L) + "\n", headers={"X-Pomodoro-Event": f"{ev.get('ev_id', 0)}:{ev.get('ev_kind', '')}:{age}",
        "X-Pomodoro-Config": f"{st['focus_min']}:{st['short_min']}:{st['long_min']}:{st['long_every']}",   # for the offline timer
        "X-Pomodoro-Projects": ",".join(urllib.parse.quote(n, safe="") for n in projects)})

@app.get("/api/export.csv")
def export(req: Request):
    need_auth(req)
    with pool.connection() as c:
        rows = c.execute("SELECT day,seconds,project,note,pomodoro FROM sessions ORDER BY day,id").fetchall()
    o = io.StringIO(); w = csv.writer(o); w.writerow(["date", "duration", "seconds", "activity", "note", "pomodoro"])
    for r in rows: w.writerow([r[0].isoformat(), "%d:%02d:%02d" % (r[1] // 3600, r[1] // 60 % 60, r[1] % 60), r[1], r[2], r[3], r[4]])
    return PlainTextResponse(o.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=pomodoro-sessions.csv"})

@app.get("/health")
def health():
    with pool.connection() as c: c.execute("SELECT 1")
    return {"ok": True}

@app.get("/manifest.webmanifest")
def manifest(): return FileResponse("static/manifest.webmanifest", media_type="application/manifest+json", headers={"Cache-Control": "no-cache"})

@app.get("/")
def index(): return FileResponse("static/index.html", headers={"Cache-Control": "no-cache"})
app.mount("/static", StaticFiles(directory="static"), name="static")
