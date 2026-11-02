import os, re, sys, time
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

def test_menubar(c):
    from fastapi.testclient import TestClient as TC
    pw = os.environ["EDIT_PASSWORD"]; c.post("/api/login", json={"password": pw}); c.delete("/api/timer")
    anon = TC(main.app, base_url="https://testserver")
    assert anon.post("/api/menubar/key").status_code == 401 and anon.get("/api/menubar").status_code == 401
    script = c.post("/api/menubar/key"); assert script.status_code == 200 and "pomodoro.1s.sh" in script.headers["content-disposition"]
    key = re.search(r'KEY="([0-9a-f]+)"', script.text).group(1)
    h = {"X-Timer-Key": key}
    assert anon.get("/api/menubar", headers={"X-Timer-Key": "bad"}).status_code == 401
    m = anon.get("/api/menubar", headers=h).text
    assert m.startswith("🍅 ") and "Start | bash=/usr/bin/curl" in m and "@KEY@" in m and "@URL@" in m
    assert anon.post("/api/timer/start", headers=h, json={}).status_code == 200
    assert anon.post("/api/timer/startp?project=Menu%20Bar", headers=h).status_code == 200
    assert anon.get("/api/timer", headers=h).json()["timer"]["project"] == "Menu Bar"
    assert "Pause | " in anon.get("/api/menubar", headers=h).text
    assert anon.post("/api/timer/pause", headers=h).status_code == 200 and anon.get("/api/menubar", headers=h).text.startswith("⏸ ")
    # the key can do nothing else
    assert anon.delete("/api/timer", headers=h).status_code == 401 and anon.get("/api/state", headers=h).json()["edit"] is False
    assert anon.post("/api/session", headers=h, json={"day": "2026-11-02", "seconds": 60}).status_code == 401
    assert anon.post("/api/password", headers=h, json={"current": pw, "new": "Another123"}).status_code == 401
    key2 = re.search(r'KEY="([0-9a-f]+)"', c.post("/api/menubar/key").text).group(1)
    assert anon.get("/api/menubar", headers=h).status_code == 401 and anon.get("/api/menubar", headers={"X-Timer-Key": key2}).status_code == 200   # new key revokes the old
    c.delete("/api/timer")
    # notification events: only the natural end of a block counts
    def ev(): return anon.get("/api/menubar", headers={"X-Timer-Key": key2}).headers["x-pomodoro-event"]
    e0 = ev(); assert e0.count(":") == 2
    c.post("/api/timer/start", json={}); c.post("/api/timer/skip"); c.post("/api/timer/pause")
    assert ev() == e0 or ev().split(":")[0] == e0.split(":")[0]                  # skip / pause: no event
    c.delete("/api/timer"); c.post("/api/timer/start", json={})
    with main.pool.connection() as db: db.execute("UPDATE timer SET start_ms=%s, acc_ms=0 WHERE id=1", (main.now_ms() - 26 * 60000,))
    main.tick(); i1, kind, age = ev().split(":"); assert int(i1) == int(e0.split(":")[0]) + 1 and kind == "focus" and int(age) < 5
    c.post("/api/timer/start", json={})
    with main.pool.connection() as db: db.execute("UPDATE timer SET start_ms=%s, acc_ms=0 WHERE id=1", (main.now_ms() - 6 * 60000,))
    main.tick(); i2, kind, _ = ev().split(":"); assert int(i2) == int(i1) + 1 and kind == "break"
    c.delete("/api/timer")

def test_offline_upload(c):
    from fastapi.testclient import TestClient as TC
    c.post("/api/login", json={"password": os.environ["EDIT_PASSWORD"]})
    anon = TC(main.app, base_url="https://testserver")
    key = re.search(r'KEY="([0-9a-f]+)"', c.post("/api/menubar/key").text).group(1); h = {"X-Timer-Key": key}
    end = int(time.time()) - 3600
    body = {"sessions": [{"id": "t1-%d" % end, "end": end, "seconds": 1500, "project": "Office"}, {"id": "bad", "end": end, "seconds": 0},
                         {"id": "old", "end": end - 90 * 86400, "seconds": 60}]}
    assert anon.post("/api/timer/offline", json=body).status_code == 401
    r = anon.post("/api/timer/offline", headers=h, json=body).json(); assert r == {"added": 1, "skipped": 2}
    assert anon.post("/api/timer/offline", headers=h, json=body).json() == {"added": 0, "skipped": 2}      # same id again: nothing added
    row = [x for x in c.get("/api/state").json()["sessions"] if x["project"] == "Office"]
    assert len(row) == 1 and row[0]["pomodoro"] and row[0]["seconds"] == 1500 and len(row[0]["end"]) == 5
    assert "Office" in [p["name"] for p in c.get("/api/state").json()["projects"]]
    hdr = anon.get("/api/menubar", headers=h).headers; assert hdr["x-pomodoro-config"].count(":") == 3 and "Office" in hdr["x-pomodoro-projects"]

def test_project_and_note_are_kept_server_side(c):
    c.post("/api/login", json={"password": os.environ["EDIT_PASSWORD"]}); c.delete("/api/timer")
    c.post("/api/timer/label", json={"project": "Documentation", "note": "SPN secret inventory"})
    t = c.get("/api/timer").json()["timer"]; assert (t["project"], t["note"]) == ("Documentation", "SPN secret inventory")
    c.post("/api/timer/startp?project=Learning")                                    # menu bar 'Start as…' changes the project, keeps the note
    t = c.get("/api/timer").json()["timer"]; assert (t["project"], t["note"]) == ("Learning", "SPN secret inventory")
    with main.pool.connection() as db: db.execute("UPDATE timer SET start_ms=%s, acc_ms=0 WHERE id=1", (main.now_ms() - 26 * 60000,))
    main.tick()                                                                     # the server closes the block with no browser open
    row = [x for x in c.get("/api/state").json()["sessions"] if x["project"] == "Learning"][0]; assert (row["note"], row["pomodoro"]) == ("SPN secret inventory", True)
    t = c.get("/api/timer").json()["timer"]; assert (t["project"], t["note"]) == ("Learning", "SPN secret inventory")   # the next block keeps the label
    c.delete("/api/timer")

def test_todos(c):
    from fastapi.testclient import TestClient as TC
    c.post("/api/login", json={"password": os.environ["EDIT_PASSWORD"]}); anon = TC(main.app, base_url="https://testserver")
    assert anon.post("/api/todo", json={"text": "x"}).status_code == 401 and anon.get("/api/state").json()["todos"] == []
    assert c.post("/api/todo", json={"text": "  "}).status_code == 400 and c.post("/api/todo", json={"text": "x", "status": "nope"}).status_code == 400
    a = c.post("/api/todo", json={"text": "Check SPN secrets"}).json()["todos"][-1]; assert a["status"] == "todo"
    b = c.post("/api/todo", json={"text": "Waiting for IT", "status": "hold"}).json()["todos"][-1]; assert b["status"] == "hold"
    assert c.post(f"/api/todo/{a['id']}", json={"status": "bad"}).status_code == 400
    st = {t["id"]: t["status"] for t in c.post(f"/api/todo/{a['id']}", json={"status": "review"}).json()["todos"]}; assert st[a["id"]] == "review" and st[b["id"]] == "hold"
    st = {t["id"]: t["status"] for t in c.post(f"/api/todo/{a['id']}", json={"status": "finished"}).json()["todos"]}; assert st[a["id"]] == "finished"
    assert anon.get("/api/state").json()["todos"] == []
    left = {t["id"]: t["status"] for t in c.delete("/api/todos/done").json()["todos"]}; assert a["id"] not in left and left[b["id"]] == "hold"   # only Finished is cleared
    assert b["id"] not in {t["id"] for t in c.delete(f"/api/todo/{b['id']}").json()["todos"]}
    l = c.post("/api/todo", json={"text": "newer"}).json()["todos"][-1]; assert l["at"] > 0

def test_todo_priority_and_order(c):
    c.post("/api/login", json={"password": os.environ["EDIT_PASSWORD"]})
    ids = [c.post("/api/todo", json={"text": "o%d" % i}).json()["todos"][-1]["id"] for i in range(4)]
    assert [t["pos"] for t in c.get("/api/state").json()["todos"] if t["id"] in ids] == sorted(t["pos"] for t in c.get("/api/state").json()["todos"] if t["id"] in ids)
    assert c.post(f"/api/todo/{ids[0]}", json={"prio": 5}).status_code == 400
    t = {x["id"]: x for x in c.post(f"/api/todo/{ids[2]}", json={"prio": 1}).json()["todos"]}; assert t[ids[2]]["prio"] == 1 and t[ids[0]]["prio"] is None
    t = {x["id"]: x for x in c.post(f"/api/todo/{ids[2]}", json={"prio": 0}).json()["todos"]}; assert t[ids[2]]["prio"] is None      # 0 clears it
    new = [ids[3], ids[1], ids[0]]                                                       # ids[2] is not on screen: it keeps its place
    order = [x["id"] for x in c.post("/api/todos/order", json={"ids": new}).json()["todos"] if x["id"] in ids]
    assert order == [ids[3], ids[2], ids[1], ids[0]] or [i for i in order if i != ids[2]] == new
    assert [i for i in order if i != ids[2]] == new
    for i in ids: c.delete(f"/api/todo/{i}")

def test_todo_sync_from_plugin(c):
    from fastapi.testclient import TestClient as TC
    c.post("/api/login", json={"password": os.environ["EDIT_PASSWORD"]}); anon = TC(main.app, base_url="https://testserver")
    key = re.search(r'KEY="([0-9a-f]+)"', c.post("/api/menubar/key").text).group(1); h = {"X-Timer-Key": key}
    a = c.post("/api/todo", json={"text": "Existing one"}).json()["todos"][-1]["id"]
    b = c.post("/api/todo", json={"text": "Existing two"}).json()["todos"][-1]["id"]
    assert anon.post("/api/todos/sync", json={"ops": []}).status_code == 401
    # the plugin's copy comes with the menu (hidden lines), P1 first
    c.post(f"/api/todo/{b}", json={"prio": 1})
    lines = [l for l in anon.get("/api/menubar", headers=h).text.splitlines() if l.startswith("@@TODO@@")]
    assert any(l.split("\t")[1] == f"s{b}" and l.split("\t")[3] == "1" for l in lines) and lines[0].split("\t")[1] == f"s{b}"
    now = int(time.time())
    ops = [{"op": "add", "ref": "c1-1", "text": "Made offline", "status": "review", "prio": 2, "t": now},
           {"op": "set", "ref": "c1-1", "status": "finished", "t": now},                  # change a to-do that was created in the same batch
           {"op": "set", "ref": f"s{a}", "status": "hold", "prio": 3, "t": now},
           {"op": "del", "ref": f"s{b}", "t": now}, {"op": "set", "ref": "s999999", "status": "hold", "t": now}, {"op": "add", "ref": "bad", "text": "x"}]
    r = anon.post("/api/todos/sync", headers=h, json={"ops": ops}).json(); assert r["skipped"] == 2
    st = {t["text"]: t for t in c.get("/api/state").json()["todos"]}
    assert st["Made offline"]["status"] == "finished" and st["Made offline"]["prio"] == 2 and st["Existing one"]["status"] == "hold" and st["Existing one"]["prio"] == 3 and "Existing two" not in st
    n = len(st); assert anon.post("/api/todos/sync", headers=h, json={"ops": ops}).status_code == 200
    assert len(c.get("/api/state").json()["todos"]) == n                                 # repeating the batch adds nothing
    # an OLD status change (made offline before the to-do was moved on the web) does not win
    c.post(f"/api/todo/{a}", json={"status": "review"})
    anon.post("/api/todos/sync", headers=h, json={"ops": [{"op": "set", "ref": f"s{a}", "status": "todo", "t": now - 3600}]})
    assert {t["id"]: t["status"] for t in c.get("/api/state").json()["todos"]}[a] == "review"
    anon.post("/api/todos/sync", headers=h, json={"ops": [{"op": "set", "ref": f"s{a}", "status": "todo", "t": now + 60}]})        # a newer one does
    assert {t["id"]: t["status"] for t in c.get("/api/state").json()["todos"]}[a] == "todo"
    assert anon.get("/api/state", headers=h).json()["todos"] == []                       # the key does not read the list through the normal API
    for t in c.get("/api/state").json()["todos"]: c.delete(f"/api/todo/{t['id']}")

def test_todo_api_token(c):
    from fastapi.testclient import TestClient as TC
    anon = TC(main.app, base_url="https://testserver")
    assert anon.post("/api/apitoken").status_code == 401 and anon.post("/api/v1/todos", json={"text": "x"}).status_code == 401
    c.post("/api/login", json={"password": os.environ["EDIT_PASSWORD"]})
    tok = c.post("/api/apitoken").json()["token"]; h = {"Authorization": "Bearer " + tok}
    assert c.get("/api/state").json()["api_token"] is True and anon.get("/api/state").json()["api_token"] is False
    assert anon.post("/api/v1/todos", headers={"Authorization": "Bearer nope"}, json={"text": "x"}).status_code == 401
    r = anon.post("/api/v1/todos", headers=h, json={"text": "Renew certificate", "prio": 2}); assert r.status_code == 201
    item = r.json(); assert item["text"] == "Renew certificate" and item["status"] == "todo" and item["prio"] == 2
    q = anon.post("/api/v1/todos?text=Buy%20milk", headers={"X-API-Key": tok}); assert q.status_code == 201 and q.json()["text"] == "Buy milk"      # query form + X-API-Key
    assert anon.post("/api/v1/todos", headers=h, json={"text": "  "}).status_code == 400
    assert anon.post("/api/v1/todos", headers=h, json={"text": "x", "status": "nope"}).status_code == 400
    assert anon.post("/api/v1/todos", headers=h, json={"text": "x", "prio": 9}).status_code == 400
    assert anon.patch(f"/api/v1/todos/{item['id']}", headers=h, json={"status": "review", "prio": 1}).json()["status"] == "review"
    assert [t["text"] for t in anon.get("/api/v1/todos?status=review", headers=h).json()] == ["Renew certificate"]
    assert anon.get("/api/v1/todos?status=bad", headers=h).status_code == 400 and anon.patch("/api/v1/todos/999999", headers=h, json={"prio": 1}).status_code == 404
    assert "Renew certificate" in [t["text"] for t in c.get("/api/state").json()["todos"]]                       # same data the web page shows
    # the token reaches nothing else
    for call in (anon.get("/api/timer", headers=h), anon.post("/api/session", headers=h, json={"day": "2026-11-02", "seconds": 60}), anon.post("/api/todo", headers=h, json={"text": "x"}),
                 anon.post("/api/menubar/key", headers=h), anon.get("/api/export.csv", headers=h)): assert call.status_code == 401
    assert anon.get("/api/state", headers=h).json()["todos"] == []
    tok2 = c.post("/api/apitoken").json()["token"]
    assert anon.get("/api/v1/todos", headers=h).status_code == 401 and anon.get("/api/v1/todos", headers={"Authorization": "Bearer " + tok2}).status_code == 200   # new token revokes the old
    assert anon.delete(f"/api/v1/todos/{item['id']}", headers={"Authorization": "Bearer " + tok2}).status_code == 200
    assert c.delete("/api/apitoken").status_code == 200 and anon.get("/api/v1/todos", headers={"Authorization": "Bearer " + tok2}).status_code == 401
    for t in c.get("/api/state").json()["todos"]: c.delete(f"/api/todo/{t['id']}")

def test_inprogress_status(c):
    c.post("/api/login", json={"password": os.environ["EDIT_PASSWORD"]})
    t = c.post("/api/todo", json={"text": "Doing it now", "status": "inprogress"}).json()["todos"][-1]; assert t["status"] == "inprogress"
    assert {x["id"]: x["status"] for x in c.post(f"/api/todo/{t['id']}", json={"status": "hold"}).json()["todos"]}[t["id"]] == "hold"
    assert {x["id"]: x["status"] for x in c.post(f"/api/todo/{t['id']}", json={"status": "inprogress"}).json()["todos"]}[t["id"]] == "inprogress"
    key = re.search(r'KEY="([0-9a-f]+)"', c.post("/api/menubar/key").text).group(1)
    from fastapi.testclient import TestClient as TC
    anon = TC(main.app, base_url="https://testserver")
    assert f"s{t['id']}\tinprogress" in anon.get("/api/menubar", headers={"X-Timer-Key": key}).text      # reaches the plugin's copy
    assert "inprogress" in anon.get("/api/menubar", headers={"X-Timer-Key": key}).text and "In Progress" in main.PLUGIN
    c.delete(f"/api/todo/{t['id']}")

def test_subtasks(c):
    from fastapi.testclient import TestClient as TC
    anon = TC(main.app, base_url="https://testserver"); c.post("/api/login", json={"password": os.environ["EDIT_PASSWORD"]})
    t = c.post("/api/todo", json={"text": "Rotate SPN secrets"}).json()["todos"][-1]; tid = t["id"]; assert t["subs"] == []
    assert anon.post(f"/api/todo/{tid}/sub", json={"text": "x"}).status_code == 401
    assert c.post(f"/api/todo/{tid}/sub", json={"text": "  "}).status_code == 400 and c.post("/api/todo/999999/sub", json={"text": "x"}).status_code == 404
    c.post(f"/api/todo/{tid}/sub", json={"text": "List expiring secrets"}); l = c.post(f"/api/todo/{tid}/sub", json={"text": "Create new secrets"}).json()["todos"]
    subs = [x for x in l if x["id"] == tid][0]["subs"]; assert [x["text"] for x in subs] == ["List expiring secrets", "Create new secrets"] and not subs[0]["done"]
    l = c.post(f"/api/sub/{subs[0]['id']}", json={"done": True}).json()["todos"]; assert [x for x in l if x["id"] == tid][0]["subs"][0]["done"] is True
    assert anon.get("/api/state").json()["todos"] == []                                       # private like the rest
    # the plugin's copy shows the progress, display only
    key = re.search(r'KEY="([0-9a-f]+)"', c.post("/api/menubar/key").text).group(1)
    assert any(l.endswith("Rotate SPN secrets (1/2)") for l in anon.get("/api/menubar", headers={"X-Timer-Key": key}).text.splitlines())
    l = c.delete(f"/api/sub/{subs[1]['id']}").json()["todos"]; assert len([x for x in l if x["id"] == tid][0]["subs"]) == 1
    # a to-do can have at most 50 subtasks
    for i in range(49): c.post(f"/api/todo/{tid}/sub", json={"text": f"s{i}"})
    assert c.post(f"/api/todo/{tid}/sub", json={"text": "one too many"}).status_code == 400
    # API
    tok = c.post("/api/apitoken").json()["token"]; h = {"Authorization": "Bearer " + tok}
    item = anon.post("/api/v1/todos", headers=h, json={"text": "With steps", "subtasks": ["one", "two", " "]}).json(); assert [x["text"] for x in item["subtasks"]] == ["one", "two"]
    item = anon.post(f"/api/v1/todos/{item['id']}/subtasks", headers=h, json={"text": "three"}).json(); assert len(item["subtasks"]) == 3
    sid = item["subtasks"][0]["id"]; assert anon.patch(f"/api/v1/subtasks/{sid}", headers=h, json={"done": True}).json()["subtasks"][0]["done"] is True
    assert anon.patch("/api/v1/subtasks/999999", headers=h, json={"done": True}).status_code == 404
    assert any(x["id"] == item["id"] and len(x["subtasks"]) == 3 for x in anon.get("/api/v1/todos", headers=h).json())
    assert anon.delete(f"/api/v1/subtasks/{sid}", headers=h).status_code == 200
    # deleting the to-do deletes its subtasks
    c.delete(f"/api/todo/{tid}"); c.delete(f"/api/todo/{item['id']}")
    with main.pool.connection() as db: assert db.execute("SELECT count(*) FROM subtasks").fetchone()[0] == 0
    c.delete("/api/apitoken")
