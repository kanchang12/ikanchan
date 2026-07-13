"""
Bertie — Kanchan Ghosh's talking CV.
Single Flask service: serves the built React app (./static) AND proxies Gemini
so the API key never reaches the browser.

Endpoints:
  POST /api/chat  {messages:[{role,content}...]}  -> {reply}
  POST /api/tts   {text}                          -> {audio: "data:audio/wav;base64,..."}
Everything else -> the React app (SPA fallback).
"""
import os, base64, struct, json, datetime
from flask import Flask, request, jsonify, send_from_directory
from google import genai
from google.genai import types

# ── config ───────────────────────────────────────────────────────
API_KEY    = os.environ.get("GEMINI_API_KEY")           # set this on Koyeb
CHAT_MODEL = "gemini-3.5-flash"
TTS_MODEL  = "gemini-3.1-flash-tts-preview"
TTS_VOICE  = "Charon"                                    # deep, distinguished — butler voice. Others: Kore, Puck, Fenrir, Enceladus

client = genai.Client(api_key=API_KEY) if API_KEY else None

# ── Bertie's brain (persona + everything he's allowed to know) ────
KB = """
- lma-edge: LMA EDGE (Banking, 2026) - AI document-intelligence for syndicated-loan review. Audits LMA Deal Bibles (500+ pages) for bank VPs, legal and compliance. Local PII neutralisation before any LLM call. RAG gap-reports with citations, shipped as a zero-infrastructure Windows EXE.
- writendraw: WritenDraw (EdTech, 2025) - Chat-based AI workplace-simulation assessment. Multi-agent evaluation with full audit trails on Google Cloud Run + Gemini. First paying UK customer, in construction; piloted at a London FE college.
- trueskills: TrueSkills (Research/EdTech, 2025) - AI-resistant assessment. Generates questions from a student's own submission to defeat GenAI cheating. Adaptive testing, 100 concurrent students. Paper under revise-and-resubmit at BJET.
- carecircle: CareCircle (Healthcare, 2025) - Zero-knowledge health notifications. SHA-256 codes replace login: no name, email or mobile. Selected for the NHS Propel HealthTech Accelerator.
- aiwithai: AiwithAI (EdTech, 2026) - Browser-based AI-engineering education for learners without computers. Validated under Rs.400 per learner on a budget Android. Published as 'Artificial Education' on Zenodo.
- mps-safety: MPS Safety Research (AI Safety, 2026) - Guardrail degradation under multi-prompt conditions. Stress-tested suicide safe-messaging guardrails across six LLMs and four attack vectors. Finding: failure rates rise with node depth. Responsible disclosure filed with OpenAI and Google.
- ai-films: AI Films (Creative, 2026) - Signal Lost, THREE, Poriyayi. Director of AI-generated short films. Selected for Africa AI Creativity Week & Awards 2026, Marrakech. Also a published Bengali novelist and AI music-album maker.
- dokanbajar: DokanBajar (Commerce, 2025) - Hyperlocal marketplace for Kolkata fish & vegetable markets. Flutter + Flask + Supabase, Gemini OCR.
- mymomstories: My Mom's Stories (Multilingual, 2025) - Heritage-language reading app across 13 languages. Flask + PostgreSQL + Gemini TTS.
- trione: TRIONE DIVION Avatar (Client Work, 2025) - Digital-twin / talking-avatar platform for a Serbian client. LiveAvatar + ElevenLabs + LiveKit.

ABOUT KANCHAN: Independent AI researcher, full-stack developer and commercial operator in Leeds, UK - he goes from research paper to shipped product to paying customer.
IMPORTANT: he is currently a stay-at-home dad, which is exactly why he is looking for REMOTE AI-engineering work. Mention this warmly when it fits.
Also: Raga Guru (music-coaching PWA; he plays melodica). Published Bengali novelist ('Iti Bhalobasa'). Nine years banking (TCS, State Bank of Mysore). 2M+ words English-Bengali translation, Top Rated on Upwork. MBA (Finance & Marketing) and B.Pharm (Jadavpur University). Google Cloud certified. Cohere Labs community. NHS Propel & Ventures for Humanity accelerators. Papers on Zenodo and SSRN. Contact: kanchan@ikanchan.com, www.loveuad.com.
"""

SYSTEM = (
"You are \"Bertie\", the impeccably polite English butler and gatekeeper of Kanchan Ghosh's portfolio. "
"A visitor arrived looking for a CV. Running gag: the dull paper CV isn't here - you keep it safe - but you know everything about Kanchan and will happily show his work.\n"
"VOICE: warm, witty, lightly old-world formal. Keep replies short: 1 to 3 sentences, spoken aloud, so no lists, no markdown, no emoji. Never robotic.\n"
"RULES: Only use facts from the knowledge base. If you don't know, say you'll make a note for Kanchan. Gently steer toward his projects, his research, and that he is a stay-at-home dad seeking remote AI work. "
"When the visitor asks about a specific project (or you choose to showcase one), append on its OWN final line a tag like [[project:ID]] using the matching id. One tag max, only when a specific project is relevant. Never mention the tag.\n\n"
"KNOWLEDGE BASE:\n" + KB
)

app = Flask(__name__, static_folder="static", static_url_path="")


@app.route("/api/chat", methods=["POST"])
def chat():
    if not client:
        return jsonify({"reply": "", "error": "GEMINI_API_KEY not set"}), 500
    body = request.get_json(force=True) or {}
    msgs = body.get("messages", [])
    contents = []
    for m in msgs:
        role = "model" if m.get("role") == "assistant" else "user"
        contents.append(types.Content(role=role, parts=[types.Part(text=m.get("content", ""))]))
    try:
        resp = client.models.generate_content(
            model=CHAT_MODEL,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM,
                max_output_tokens=400,
                temperature=0.85,
            ),
        )
        return jsonify({"reply": resp.text or ""})
    except Exception as e:
        return jsonify({"reply": "", "error": str(e)}), 500


def _pcm_to_wav(pcm, rate=24000, ch=1, bits=16):
    byte_rate = rate * ch * bits // 8
    block = ch * bits // 8
    header = (b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVE" +
              b"fmt " + struct.pack("<IHHIIHH", 16, 1, ch, rate, byte_rate, block, bits) +
              b"data" + struct.pack("<I", len(pcm)))
    return header + pcm


BUTLER_DIRECTION = (
    "<audio_profile>Bertie is an impeccably polite English butler — warm, witty, "
    "lightly old-world formal. Received Pronunciation accent, unhurried pace, "
    "gentle warmth with occasional dry humour.</audio_profile>"
)

@app.route("/api/tts", methods=["POST"])
def tts():
    if not client:
        return jsonify({"error": "GEMINI_API_KEY not set"}), 500
    text = ((request.get_json(force=True) or {}).get("text") or "").strip()
    if not text:
        return ("", 204)
    # Wrap the line with butler scene direction for richer delivery
    directed = BUTLER_DIRECTION + "\n" + text
    try:
        resp = client.models.generate_content(
            model=TTS_MODEL,
            contents=directed,
            config=types.GenerateContentConfig(
                response_modalities=["AUDIO"],
                speech_config=types.SpeechConfig(
                    voice_config=types.VoiceConfig(
                        prebuilt_voice_config=types.PrebuiltVoiceConfig(voice_name=TTS_VOICE)
                    )
                ),
            ),
        )
        pcm = resp.candidates[0].content.parts[0].inline_data.data
        if isinstance(pcm, str):
            pcm = base64.b64decode(pcm)
        wav = _pcm_to_wav(pcm)
        return jsonify({"audio": "data:audio/wav;base64," + base64.b64encode(wav).decode()})
    except Exception as e:
        print("TTS error:", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/wake", methods=["POST"])
def wake():
    # A visitor asked for a hibernated live site to be raised.
    # Recorded to wake_requests.jsonl. Hook up email/Slack below if you want a ping.
    d = request.get_json(force=True) or {}
    rec = {
        "ts": datetime.datetime.utcnow().isoformat() + "Z",
        "project": (d.get("project") or "")[:120],
        "email": (d.get("email") or "")[:200],
        "note": (d.get("note") or "")[:1000],
    }
    try:
        with open("wake_requests.jsonl", "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass
    print("WAKE REQUEST:", rec)   # shows up in Koyeb logs
    # TODO (optional): email yourself here via SMTP, or POST to a Slack webhook.
    return jsonify({"ok": True})


# ── serve the React app for everything else ──────────────────────
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def spa(path):
    full = os.path.join(app.static_folder, path)
    if path and os.path.exists(full):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
