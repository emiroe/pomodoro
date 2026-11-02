import os, hmac, hashlib, time, datetime, csv, io
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
CREATE INDEX IF NOT EXISTS sessions_day ON sessions(day);
CREATE TABLE IF NOT EXISTS projects (name text PRIMARY KEY, color text NOT NULL DEFAULT '#7c9cff', position serial);
CREATE TABLE IF NOT EXISTS settings (key text PRIMARY KEY, value text NOT NULL);
INSERT INTO settings VALUES ('focus_min','25'),('short_min','5'),('long_min','15'),('long_every','4'),('daily_goal','8') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS timer (id int PRIMARY KEY DEFAULT 1 CHECK (id = 1), phase text NOT NULL DEFAULT 'focus', dur_ms bigint NOT NULL,
  acc_ms bigint NOT NULL DEFAULT 0, start_ms bigint NOT NULL DEFAULT 0, project text NOT NULL DEFAULT '', note text NOT NULL DEFAULT '', cycle int NOT NULL DEFAULT 0);
"""
LIMITS = {"focus_min": (1, 180), "short_min": (1, 60), "long_min": (1, 120), "long_every": (2, 12), "daily_goal": (1, 40)}

@asynccontextmanager
async def lifespan(app):
    pool.open(wait=True)
    with pool.connection() as c: c.execute(SCHEMA)
    yield
    pool.close()

app = FastAPI(lifespan=lifespan)

def sign(ts): return hmac.new(SECRET, str(ts).encode(), hashlib.sha256).hexdigest()
def authed(req: Request):
    try: ts, sig = req.cookies.get("pm_auth", "").split(".")
    except ValueError: return False
    return hmac.compare_digest(sig, sign(ts)) and time.time() - int(ts) < 90 * 86400
def need_auth(req):
    if not authed(req): raise HTTPException(401, "login required")
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
    if not PASSWORD or not hmac.compare_digest(b.password, PASSWORD): raise HTTPException(403, "wrong password")
    ts = int(time.time())
    resp.set_cookie("pm_auth", "%d.%s" % (ts, sign(ts)), max_age=90 * 86400, httponly=True, samesite="lax", secure=True)
    return {"ok": True}

@app.post("/api/logout")
def logout(resp: Response):
    resp.delete_cookie("pm_auth"); return {"ok": True}

def srow(r): return {"id": r[0], "day": r[1].isoformat(), "seconds": r[2], "project": r[3], "note": r[4], "pomodoro": r[5]}
def get_settings(c): return {k: int(v) for k, v in c.execute("SELECT key,value FROM settings").fetchall()}

@app.get("/api/state")
def state(req: Request):
    with pool.connection() as c:
        rows = c.execute("SELECT id,day,seconds,project,note,pomodoro FROM sessions ORDER BY day DESC, id DESC").fetchall()
        projects = [{"name": r[0], "color": r[1]} for r in c.execute("SELECT name,color FROM projects ORDER BY position").fetchall()]
        st = get_settings(c)
    return {"edit": authed(req), "sessions": [srow(r) for r in rows], "projects": projects, "settings": st, "today": today().isoformat()}

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
        c.execute("INSERT INTO sessions(day,seconds,project,note,pomodoro) VALUES (%s,%s,%s,%s,true)", (day, min(86400, log_seconds), project, note))
    nxt, cycle = next_phase(c, phase, cycle) if (phase != "focus" or log_seconds > 0) else (phase, cycle)
    c.execute("UPDATE timer SET phase=%s,dur_ms=%s,acc_ms=0,start_ms=0,cycle=%s WHERE id=1", (nxt, phase_ms(get_settings(c), nxt), cycle))

class TimerStart(BaseModel): project: str | None = None; note: str | None = None
@app.get("/api/timer")
def timer_get(req: Request):
    need_auth(req)
    with pool.connection() as c: return timer_state(c)

@app.post("/api/timer/start")
def timer_start(b: TimerStart, req: Request):
    need_auth(req)
    with pool.connection() as c:
        timer_state(c)
        if b.project is not None: c.execute("UPDATE timer SET project=%s,note=%s WHERE id=1", (ensure_project(c, b.project), (b.note or "")[:300]))
        c.execute("UPDATE timer SET start_ms=%s WHERE id=1 AND start_ms=0", (now_ms(),))
        return timer_state(c)

@app.post("/api/timer/pause")
def timer_pause(req: Request):
    need_auth(req)
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

@app.post("/api/timer/complete")
def timer_complete(req: Request):
    # only acts when the countdown really reached 0 on the server clock
    need_auth(req)
    with pool.connection() as c:
        s = timer_state(c)["timer"]
        el = s["acc"] + (now_ms() - s["start"] if s["start"] else 0)
        if el >= s["dur"]:
            end = s["start"] + (s["dur"] - s["acc"]) if s["start"] else now_ms()
            move_on(c, s["dur"] // 1000, end)
        return timer_state(c)

@app.post("/api/timer/finish")
def timer_finish(req: Request):
    # 'Log it now': stop a focus block early and log the time done so far (needs at least 1 minute)
    need_auth(req)
    with pool.connection() as c:
        s = timer_state(c)["timer"]
        el = s["acc"] + (now_ms() - s["start"] if s["start"] else 0)
        if s["phase"] != "focus" or el < 60000: raise HTTPException(400, "nothing to log yet")
        move_on(c, el // 1000, now_ms())
        return timer_state(c)

@app.post("/api/timer/skip")
def timer_skip(req: Request):
    # skip a break (or drop a focus block without logging it)
    need_auth(req)
    with pool.connection() as c:
        s = timer_state(c)["timer"]
        if s["phase"] == "focus":
            c.execute("UPDATE timer SET acc_ms=0,start_ms=0 WHERE id=1")
        else: move_on(c, 0, now_ms())
        return timer_state(c)

@app.delete("/api/timer")
def timer_reset(req: Request):
    need_auth(req)
    with pool.connection() as c:
        c.execute("DELETE FROM timer WHERE id=1")
        return timer_state(c)

@app.get("/api/export.csv")
def export(req: Request):
    need_auth(req)
    with pool.connection() as c:
        rows = c.execute("SELECT day,seconds,project,note,pomodoro FROM sessions ORDER BY day,id").fetchall()
    o = io.StringIO(); w = csv.writer(o); w.writerow(["date", "duration", "seconds", "project", "note", "pomodoro"])
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
