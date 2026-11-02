# Pomodoro
Work tracker with a shared server-side pomodoro timer. FastAPI + Postgres, one page `app/static/index.html`. Live: https://pomodoro.romijn.app (view open, editing needs the edit password).

## To-do API
Make a token in the app under ⚙ > To-do API (shown once; a new one replaces the old). It only works on `/api/v1/todos*`.
```
curl -X POST https://pomodoro.romijn.app/api/v1/todos -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
     -d '{"text":"Renew certificate","status":"todo","prio":2}'          # status: todo|hold|review|finished, prio: 0 (none)-4
curl -X POST -H "Authorization: Bearer <token>" "https://pomodoro.romijn.app/api/v1/todos?text=Buy%20milk"      # simplest form
curl -H "Authorization: Bearer <token>" "https://pomodoro.romijn.app/api/v1/todos?status=todo"                   # list
curl -X PATCH  .../api/v1/todos/ID -d '{"status":"finished"}' ...      curl -X DELETE .../api/v1/todos/ID ...
```
`X-API-Key: <token>` works instead of the Authorization header.
