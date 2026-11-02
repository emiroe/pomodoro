import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
os.chdir(os.path.join(os.path.dirname(__file__), "..", "app"))
from fastapi.testclient import TestClient
import main, pytest

@pytest.fixture(scope="module")
def c():
    with TestClient(main.app, base_url="https://testserver") as cl: yield cl

def test_flow(c):
    if True:
        assert c.get("/health").json()["ok"]
        s = c.get("/api/state").json()
        assert s["edit"] is False and s["settings"]["focus_min"] == 25 and s["sessions"] == []
        body = {"day": "2026-11-02", "seconds": 1500, "project": "Work", "note": "x"}
        assert c.post("/api/session", json=body).status_code == 401
        assert c.get("/api/timer").status_code == 401
        assert c.post("/api/login", json={"password": "wrong"}).status_code == 403
        assert c.post("/api/login", json={"password": os.environ["EDIT_PASSWORD"]}).status_code == 200
        assert c.post("/api/session", json=dict(body, day="xx")).status_code == 400
        assert c.post("/api/session", json=dict(body, seconds=0)).status_code == 400
        i = c.post("/api/session", json=body).json()["id"]
        assert c.post("/api/session", json=dict(body, id=i, seconds=3600)).status_code == 200
        st = c.get("/api/state").json()
        assert st["sessions"][0]["seconds"] == 3600 and [p["name"] for p in st["projects"]] == ["Work"]
        assert c.post("/api/settings", json={"focus_min": 0}).status_code == 400
        assert "Work" in c.get("/api/export.csv").text
        assert c.delete(f"/api/session/{i}").status_code == 200

def test_timer(c):
    if True:
        c.post("/api/login", json={"password": os.environ["EDIT_PASSWORD"]})
        c.delete("/api/timer"); c.post("/api/settings", json={"focus_min": 1, "long_every": 2})
        c.delete("/api/timer")
        t = c.get("/api/timer").json()["timer"]
        assert t["phase"] == "focus" and t["dur"] == 60000 and t["start"] == 0
        assert c.post("/api/timer/complete").json()["timer"]["phase"] == "focus"      # not finished: nothing happens
        assert c.post("/api/timer/finish").status_code == 400                         # under a minute
        c.post("/api/timer/start", json={"project": "Deep", "note": "n"})
        c.post("/api/timer/pause"); assert c.get("/api/timer").json()["timer"]["start"] == 0
        n0 = len(c.get("/api/state").json()["sessions"])
        for k in range(2):                                                            # two full pomodoros -> second is followed by a long break
            c.post("/api/timer/start", json={"project": "Deep"})
            with main.pool.connection() as db: db.execute("UPDATE timer SET start_ms=%s, acc_ms=0 WHERE id=1", (main.now_ms() - 61000,))
            t = c.post("/api/timer/complete").json()["timer"]
            assert t["phase"] == ("short" if k == 0 else "long") and t["start"] == 0
            assert c.post("/api/timer/complete").json()["timer"]["phase"] == t["phase"]   # idempotent
            t = c.post("/api/timer/skip").json()["timer"]; assert t["phase"] == "focus"
        ss = c.get("/api/state").json()["sessions"]
        assert len(ss) == n0 + 2 and ss[0]["pomodoro"] and ss[0]["project"] == "Deep" and ss[0]["seconds"] == 60
        assert len(ss[0]["end"]) == 5 and ss[0]["start"] != ss[0]["end"] and ss[1]["end"] <= ss[0]["end"] or ss[1]["day"] != ss[0]["day"]   # clock times HH:MM, newest first
        c.post("/api/timer/start", json={"project": "Auto"})                          # the server ticker closes a due block by itself
        with main.pool.connection() as db: db.execute("UPDATE timer SET start_ms=%s, acc_ms=0 WHERE id=1", (main.now_ms() - 61000,))
        main.tick()
        t = c.get("/api/timer").json()["timer"]; assert t["phase"] in ("short", "long") and t["start"] == 0
        assert c.get("/api/state").json()["sessions"][0]["project"] == "Auto"
        c.post("/api/timer/skip"); c.post("/api/timer/start", json={})
        with main.pool.connection() as db: db.execute("UPDATE timer SET acc_ms=90000, start_ms=0 WHERE id=1")   # paused after 90 s
        assert c.post("/api/timer/finish").json()["timer"]["phase"] in ("short", "long")
        c.post("/api/settings", json={"focus_min": 25, "long_every": 4})
        # Reset Day logs the unfinished focus block under the day it was started, then resets everything
        c.post("/api/timer/skip"); c.delete("/api/timer"); c.post("/api/timer/start", json={"project": "Late", "note": "half"})
        with main.pool.connection() as db: db.execute("UPDATE timer SET acc_ms=125000, start_ms=0, day='2026-11-01' WHERE id=1")
        r = c.delete("/api/timer").json()
        assert r["logged"] == 125 and r["timer"]["cycle"] == 0 and r["timer"]["phase"] == "focus" and r["timer"]["acc"] == 0
        row = [x for x in c.get("/api/state").json()["sessions"] if x["project"] == "Late"][0]
        assert row["day"] == "2026-11-01" and row["seconds"] == 125 and row["note"] == "half" and row["pomodoro"] is False
        assert c.delete("/api/timer").json()["logged"] == 0

def test_password(c):
    pw = os.environ["EDIT_PASSWORD"]
    c.post("/api/login", json={"password": pw})
    assert c.post("/api/password", json={"current": "nope", "new": "Another123"}).status_code == 403
    assert c.post("/api/password", json={"current": pw, "new": "short"}).status_code == 400
    other = TestClient(main.app, base_url="https://testserver"); assert other.post("/api/login", json={"password": pw}).status_code == 200
    assert other.get("/api/timer").status_code == 200
    assert c.post("/api/password", json={"current": pw, "new": "Another123"}).status_code == 200
    assert c.get("/api/timer").status_code == 200                 # this device stays signed in
    assert other.get("/api/timer").status_code == 401             # the other device is signed out
    assert "pw_hash" not in c.get("/api/state").json()["settings"]
    assert TestClient(main.app, base_url="https://testserver").post("/api/login", json={"password": pw}).status_code == 403
    assert TestClient(main.app, base_url="https://testserver").post("/api/login", json={"password": "Another123"}).status_code == 200
    with main.pool.connection() as db: db.execute("DELETE FROM settings WHERE key IN ('pw_hash','pw_ver')")   # recovery path: .env password works again
    assert TestClient(main.app, base_url="https://testserver").post("/api/login", json={"password": pw}).status_code == 200
