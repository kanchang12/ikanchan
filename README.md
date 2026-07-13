# CV — Kanchan Ghosh (the talking butler)

A one-page CV that sits quietly on screen. After a random 5–20 seconds, **Bertie**
the butler pops out of the middle of the page and says hello. Ring for him and he
talks — powered by **Gemini 3.5 Flash** (brain) and **Gemini TTS** (voice) — pulling
up projects with their demo videos as you ask.

One Flask service does everything: it serves the built React app **and** proxies
Gemini, so your API key never touches the browser.

---

## Folder structure

```
kanchan-cv/
├── app.py                 ← Flask: serves the site + /api/chat + /api/tts + /api/wake
├── requirements.txt
├── Procfile               ← start command for Koyeb (gunicorn)
├── .env.example           ← copy to .env for local dev
├── static/                ← the BUILT React app (already built for you)
│   ├── index.html
│   └── assets/…
└── frontend/              ← React source (only needed if you want to change the UI)
    ├── package.json
    ├── vite.config.js
    ├── index.html
    └── src/
        ├── main.jsx
        ├── App.jsx        ← projects, videos, persona live here
        ├── butler-idle.png
        └── butler-bow.png
```

`static/` is already built and committed, so **to deploy you only need Python.**
You only touch `frontend/` if you want to change how it looks.

---

## 1. Get a Gemini API key

Google AI Studio → create an API key. That single key covers both the chat model
and the TTS model.

---

## 2. Run it locally (production mode — the simple way)

```bash
pip install -r requirements.txt
export GEMINI_API_KEY=your_key        # Windows: set GEMINI_API_KEY=your_key
python app.py
```

Open http://localhost:8000 — that's the whole app, exactly as it deploys.

---

## 3. Deploy to Koyeb

1. Push this folder to a GitHub repo (keep the `static/` folder in the commit).
2. Koyeb → **Create Web Service** → connect the repo.
3. Builder: **Buildpack** (it auto-detects Python from `requirements.txt`).
4. **Run command:**
   ```
   gunicorn app:app --bind 0.0.0.0:$PORT
   ```
5. **Environment variables:** add `GEMINI_API_KEY` = your key.
6. Deploy. Koyeb gives you a public URL — that's your portfolio.

That's it. No Node on the server, no separate frontend host, key stays server-side.

---

## Changing things

- **Projects / demo videos:** `frontend/src/App.jsx`, the `PROJECTS` array at the top.
  `video` is a YouTube id; swap ids to re-map a clip to a different project.
- **What Bertie knows / how he speaks:** `app.py`, the `KB` and `SYSTEM` strings.
- **Models:** `app.py` top — `CHAT_MODEL`, `TTS_MODEL`, `TTS_VOICE`.
  (If `gemini-3.1-flash-tts-preview` is enabled on your key, use it for TTS.)
- **After editing `frontend/`:** rebuild so `static/` updates:
  ```bash
  cd frontend
  npm install
  npm run build      # writes into ../static
  ```

---

## Hibernated live sites & the wake-up form

The project cards no longer link to live sites (they hibernate to save cost).
Instead each one shows a short note and a small form. When a visitor leaves their
email, it POSTs to `/api/wake` and is appended to `wake_requests.jsonl` (and printed
to the Koyeb logs). If you want an actual ping — email or Slack — there's a clearly
marked `TODO` in the `wake()` function in `app.py`.

---

## Voice note

Gemini TTS gives Bertie a natural voice. If a TTS call ever fails, the frontend
automatically falls back to the browser's built-in voice, so he always speaks.
The very first "hello" on his surprise entrance may be silent until the visitor's
first click (browsers block audio before any interaction) — once they ring the
bell, every line after that is spoken.
