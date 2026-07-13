import React, { useState, useEffect, useRef } from "react";
import IDLE_IMG from "./butler-idle.png";
import BOW_IMG  from "./butler-bow.png";

const PROJECTS = [
  { id:"lma-edge",    name:"LMA EDGE",            cat:"Banking",        year:"2026", video:"ujEeGC7_2jw",
    blurb:"AI document-intelligence for syndicated-loan review.",
    points:["Audits LMA Deal Bibles (500+ pages) for bank VPs, legal and compliance teams.","Local PII neutralisation — sensitive deal terms never leave the machine.","RAG gap-reports with citations, shipped as a zero-infrastructure Windows EXE."]},
  { id:"writendraw",  name:"WritenDraw",           cat:"EdTech",         year:"2025", video:"Q1MO2xNM3UY", link:"https://writendraw.com/",
    blurb:"Chat-based AI workplace-simulation assessment.",
    points:["Multi-agent evaluation with full audit trails on Google Cloud Run + Gemini.","First paying UK customer in construction; piloted at a London FE college.","Built on the TrueSkills anti-cheating research."]},
  { id:"trueskills",  name:"TrueSkills",           cat:"Research·EdTech",year:"2025", video:"7WOP9gosheA", link:"https://trueskills.uk/",
    blurb:"AI-resistant assessment through personalised understanding.",
    points:["Generates questions from a student's own submission to defeat GenAI cheating.","Adaptive testing, 100 concurrent students.","Paper under revise-and-resubmit at BJET."]},
  { id:"carecircle",  name:"CareCircle",           cat:"Healthcare",     year:"2025", video:"2c3ULCUq8-0", link:"https://www.carecircle.top/",
    blurb:"Zero-knowledge health notifications.",
    points:["SHA-256 codes replace login — no name, email or mobile number.","Eliminates the data-breach surface entirely; privacy by design.","Selected for the NHS Propel HealthTech Accelerator."]},
  { id:"aiwithai",    name:"AiwithAI",             cat:"EdTech",         year:"2026", video:"3ANmfbwMti4", link:"https://aiwithai.online/",
    blurb:"Browser-based AI-engineering education for learners without computers.",
    points:["Validated under Rs.400 per learner on a budget Android phone.","Designed for low-infrastructure environments.","Published as 'Artificial Education' on Zenodo."]},
  { id:"mps-safety",  name:"MPS Safety Research",  cat:"AI Safety",      year:"2026", video:"hWUkVUQeiys",
    blurb:"Guardrail degradation under multi-prompt conditions.",
    points:["Stress-tested suicide safe-messaging guardrails across six LLMs, four attack vectors.","Finding: failure rates rise with node depth.","Responsible disclosure filed with OpenAI and Google."]},
  { id:"ai-films",    name:"AI Films",             cat:"Creative",       year:"2026", video:"f8vnUIgTNPc",
    blurb:"Signal Lost, THREE and Poriyayi.",
    points:["Director of AI-generated short films — script to screen, fully AI-powered.","Selected for Africa AI Creativity Week & Awards 2026, Marrakech.","Also a published Bengali novelist and AI music-album maker."]},
  { id:"dokanbajar",  name:"DokanBajar",           cat:"Commerce",       year:"2025", video:"9hATQ3_eN2s",
    blurb:"Hyperlocal marketplace for Kolkata fish & vegetable markets.",
    points:["Flutter + Flask + Supabase, Gemini OCR for listings.","Built for real neighbourhood vendors.","Part of a wider set of commerce demos."]},
  { id:"mymomstories",name:"My Mom's Stories",     cat:"Multilingual",   year:"2025", video:"",
    blurb:"Heritage-language reading app across 13 languages.",
    points:["Flask + PostgreSQL + Gemini TTS.","Built to keep diaspora children connected to a mother tongue.","2M+ words of English-Bengali translation experience."]},
  { id:"trione",      name:"TRIONE Avatar",        cat:"Client Work",    year:"2025", video:"",
    blurb:"Digital-twin / talking-avatar platform for a Serbian client.",
    points:["LiveAvatar + ElevenLabs + LiveKit.","Real-time speaking avatar for client Petar.","Commissioned commercial engagement."]},
];

const KB = PROJECTS.map(p=>`- ${p.id}: ${p.name} (${p.cat}, ${p.year}) — ${p.blurb} ${p.points.join(" ")}`).join("\n")
  + "\n\nABOUT KANCHAN: Independent AI researcher, full-stack developer and commercial operator in Leeds, UK. Goes from research paper to shipped product to paying customer. Currently a stay-at-home dad seeking REMOTE AI-engineering work. MBA (Finance & Marketing, top of class), B.Pharm (Jadavpur University). Google Cloud certified. Cohere Labs community. NHS Propel & Ventures for Humanity accelerators. Published Bengali novelist ('Iti Bhalobasa'). Melodica player. 2M+ words English-Bengali translation, Top Rated on Upwork. Nine years banking (TCS, State Bank of Mysore). Contact: kanchan@ikanchan.com, www.loveuad.com.";

const SYSTEM = `You are "Bertie", an impeccably polite English butler and gatekeeper of Kanchan Ghosh's portfolio. Running gag: the dull paper CV isn't here but you know everything about Kanchan.
VOICE: warm, witty, lightly old-world formal. 1-3 sentences max. No lists, no markdown, no emoji.
RULES: Only use facts from the knowledge base. When showcasing a project append [[project:ID]] alone on the final line. Never mention the tag.
KNOWLEDGE BASE:
${KB}`;

const HELLO  = "Oh — hello, sir. I didn't hear you come in.";
const GREET  = "You rang? Splendid. You came for a CV, I take it — I'm afraid the dull paper one stays in my drawer, but I keep everything up here. Ask me anything about Kanchan: his projects, his papers, whether he's free for work.";

/* ─────────────────────────────────── STYLES ─────────────────────────────── */
const CSS = `
*{box-sizing:border-box;margin:0;padding:0}
:root{--p:#EAE1CE;--p2:#DFD3B8;--ink:#2B2620;--ink2:#6B6152;--ox:#7C2B2B;--ox2:#9B3A3A;--bl:#F1DAD6;--room:#241f1b;--gold:#C6A24A}
body{overflow:hidden;font-family:'Segoe UI',sans-serif}

/* ROOT CONTAINER — exact viewport, column flex */
.app{
  position:fixed;inset:0;
  display:flex;flex-direction:column;
  background:radial-gradient(1200px 700px at 50% -10%,#3a322b,#211d19 55%,#171310);
  color:var(--ink);padding:10px 14px 10px;gap:8px
}
.ttl{color:#F3ECDD;font-family:Georgia,serif;font-size:20px;font-weight:600;text-align:center;flex:0 0 auto}

/* MAIN AREA — takes all remaining height */
.main{flex:1 1 0;min-height:0;display:flex;overflow:hidden}

/* ── CV PHASE ── */
.cvwrap{width:100%;overflow-y:auto;display:flex;align-items:flex-start;justify-content:center;padding:8px 0;position:relative}
.cvpaper{width:460px;max-width:92vw;background:var(--p);border:1px solid #cbbd9f;border-radius:6px;padding:26px 28px 20px;box-shadow:0 20px 50px rgba(0,0,0,.5)}
.cv-name{font-family:Georgia,serif;font-size:24px;font-weight:700}
.cv-role{color:var(--ox);font-weight:600;font-size:12px;letter-spacing:.03em;margin:2px 0 5px}
.cv-contact{font-size:11px;color:var(--ink2);margin-bottom:10px}
.cv-rule{height:2px;background:var(--ox);opacity:.6;margin:6px 0 12px}
.cv-h{font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--ink2);font-weight:700;margin:13px 0 4px}
.cv-p{font-size:12px;line-height:1.6}.cv-p b{color:var(--ink)}
.cv-foot{margin-top:14px;border-top:1px solid #cdbf9f;padding-top:7px;text-align:center;font-family:Georgia,serif;font-style:italic;color:var(--ink2);font-size:11px}

/* butler pop-in over CV */
.emerge{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);z-index:5;display:flex;flex-direction:column;align-items:center;animation:emerge .7s cubic-bezier(.34,1.56,.64,1) both}
@keyframes emerge{0%{opacity:0;transform:translate(-50%,-40%) scale(.3)}60%{transform:translate(-50%,-54%) scale(1.04)}100%{opacity:1;transform:translate(-50%,-50%) scale(1)}}
.bubble{background:#fff;border:1px solid #cbbd9f;border-radius:14px;padding:7px 14px;font-family:Georgia,serif;font-size:13px;position:relative;margin-bottom:-3px;box-shadow:0 8px 18px rgba(0,0,0,.25)}
.bubble:after{content:'';position:absolute;bottom:-7px;left:24px;border:7px solid transparent;border-top-color:#fff}
.popimg{height:300px;max-height:45vh;filter:drop-shadow(0 20px 24px rgba(0,0,0,.55))}
.ringbtn{margin-top:12px;background:var(--ox);color:#fff;border:none;border-radius:999px;padding:11px 22px;font-size:13px;font-weight:600;cursor:pointer;box-shadow:0 10px 20px rgba(0,0,0,.4)}
.ringbtn:hover{background:var(--ox2)}

/* ── CHAT PHASE — two columns, total height = .main ── */
.hall{width:100%;height:100%;display:flex;gap:12px;overflow:hidden}

/* LEFT: butler portrait */
.bcol{flex:0 0 240px;border-radius:12px;overflow:hidden;position:relative;
  background:radial-gradient(240px 280px at 50% 74%,var(--bl),#5a4a44 46%,var(--room));
  display:flex;align-items:flex-end;justify-content:center;
  box-shadow:inset 0 0 60px rgba(0,0,0,.5)}
.bidleimg{height:90%;filter:drop-shadow(0 16px 18px rgba(0,0,0,.45));animation:sway 5s ease-in-out infinite}
@keyframes sway{0%,100%{transform:translateY(0)}50%{transform:translateY(-5px)}}
.bplate{position:absolute;top:10px;left:10px;background:rgba(15,10,8,.75);color:#F3ECDD;border:1px solid var(--gold);border-radius:7px;padding:5px 10px}
.bplate b{display:block;font-family:Georgia,serif;font-size:13px}
.bplate span{font-size:9px;color:var(--gold);letter-spacing:.12em;text-transform:uppercase}
.voicetgl{position:absolute;top:10px;right:10px;background:rgba(15,10,8,.75);color:#F3ECDD;border:1px solid var(--gold);border-radius:7px;padding:5px 9px;font-size:11px;cursor:pointer}

/* RIGHT: chat column — flex column, msgs scroll, rest fixed */
.ccol{flex:1 1 0;min-width:0;background:var(--p);border:1px solid #cbbd9f;border-radius:12px;display:flex;flex-direction:column;overflow:hidden}
.chead{flex:0 0 auto;background:linear-gradient(180deg,#33291f,#241d16);color:#F3ECDD;padding:12px 16px;font-family:Georgia,serif;display:flex;align-items:center;gap:8px}
.chead .dot{width:8px;height:8px;border-radius:50%;background:#7dd08e;box-shadow:0 0 8px #7dd08e}
.chead small{margin-left:auto;color:var(--gold);font:600 9px 'Segoe UI',sans-serif;letter-spacing:.12em;text-transform:uppercase}
.msgs{flex:1 1 0;overflow-y:auto;padding:14px;display:flex;flex-direction:column;gap:10px}
.row{display:flex}.row.u{justify-content:flex-end}
.bub{max-width:82%;padding:9px 13px;border-radius:13px;font-size:13px;line-height:1.5}
.bub.a{background:#fff;border:1px solid #d9cbac;border-bottom-left-radius:3px;color:var(--ink)}
.bub.u{background:var(--ox);color:#fff;border-bottom-right-radius:3px}
.dots{display:inline-flex;gap:3px;align-items:center}
.dots i{width:5px;height:5px;border-radius:50%;background:var(--ink2);animation:blink 1.2s infinite}
.dots i:nth-child(2){animation-delay:.2s}.dots i:nth-child(3){animation-delay:.4s}
@keyframes blink{0%,100%{opacity:.2}50%{opacity:1}}
.chips{flex:0 0 auto;display:flex;gap:6px;overflow-x:auto;padding:8px 12px;border-top:1px solid #d9cbac;background:var(--p2)}
.chip{white-space:nowrap;background:#fff;border:1px solid #cdbf9f;border-radius:999px;padding:5px 11px;font-size:11px;color:var(--ink);cursor:pointer;flex-shrink:0}
.chip:hover{background:var(--bl);border-color:var(--ox)}
.inbar{flex:0 0 auto;display:flex;gap:6px;padding:10px 12px;border-top:1px solid #d9cbac;background:var(--p)}
.inbar input{flex:1;border:1px solid #cbbd9f;border-radius:9px;padding:10px 12px;font-size:13px;background:#fff;color:var(--ink);outline:none}
.inbar input:focus{border-color:var(--ox)}
.micbtn{background:none;border:1px solid #cbbd9f;border-radius:9px;padding:0 12px;font-size:18px;cursor:pointer;color:var(--ink2);flex:0 0 auto}
.micbtn:hover{background:var(--bl)}.micbtn.on{background:var(--ox);color:#fff;border-color:var(--ox);animation:pulse 1s ease infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.55}}
.sendbtn{background:var(--ox);color:#fff;border:none;border-radius:9px;padding:0 16px;font-size:13px;font-weight:600;cursor:pointer;flex:0 0 auto}
.sendbtn:hover{background:var(--ox2)}.sendbtn:disabled{opacity:.45;cursor:default}

/* project modal */
.backdrop{position:fixed;inset:0;background:rgba(15,10,8,.65);z-index:40;display:flex;align-items:center;justify-content:center;padding:16px}
.card{background:var(--p);border:1px solid #c3b393;border-radius:14px;width:600px;max-width:100%;max-height:88vh;overflow-y:auto;box-shadow:0 28px 65px rgba(0,0,0,.55);position:relative}
.card .vid{width:100%;aspect-ratio:16/9;background:#000;border-radius:14px 14px 0 0;overflow:hidden;position:relative}
.card .vid iframe{position:absolute;inset:0;width:100%;height:100%;border:0}
.card .novid{aspect-ratio:16/9;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#33291f,#241d16);color:var(--gold);font-size:13px;border-radius:14px 14px 0 0}
.card .body{padding:18px 20px 22px}
.card .cx{position:absolute;top:10px;right:10px;z-index:2;background:rgba(15,10,8,.72);color:#fff;border:none;width:30px;height:30px;border-radius:50%;font-size:15px;cursor:pointer}
.card h3{font-family:Georgia,serif;font-size:20px;margin:0 0 3px}
.card .meta{color:var(--ox);font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;margin-bottom:10px}
.card ul{margin:0 0 12px;padding-left:16px}.card li{font-size:13px;line-height:1.55;margin:5px 0}
.card .lks{display:flex;gap:8px;flex-wrap:wrap}
.card .lk{text-decoration:none;font-size:12px;font-weight:600;padding:8px 13px;border-radius:9px;border:1px solid var(--ox);color:var(--ox)}
.card .lk.f{background:var(--ox);color:#fff}
.wake{margin-top:12px;background:#fff;border:1px solid #d9cbac;border-radius:10px;padding:11px 13px}
.wake p{font-size:12px;color:var(--ink2);margin-bottom:8px}
.wake input{width:100%;border:1px solid #cbbd9f;border-radius:7px;padding:8px 10px;font-size:12px;margin-bottom:6px;outline:none}
.wake input:focus{border-color:var(--ox)}
.wake button{background:var(--ox);color:#fff;border:none;border-radius:7px;padding:8px 14px;font-size:12px;font-weight:600;cursor:pointer}
.wake.ok{color:#2e6b3a;font-size:12px;font-weight:600}

@media(max-width:680px){
  .hall{flex-direction:column}
  .bcol{flex:0 0 160px}
}
@media(prefers-reduced-motion:reduce){.emerge,.bidleimg,.micbtn,.ringbtn{animation:none}}
`;

/* ─────────────────────────────── WAKEBOX ─────────────────────────────────── */
function WakeBox({project}){
  const [email,setEmail]=useState(""); const [note,setNote]=useState(""); const [sent,setSent]=useState(false);
  async function go(){ if(!email.trim()) return;
    try{ await fetch("/api/wake",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({project,email,note})}); }catch(e){}
    setSent(true); }
  if(sent) return <div className="wake ok">✓ Request sent — Kanchan will raise the site shortly.</div>;
  return <div className="wake">
    <p>⏸ This site is hibernated to keep costs down. Leave your email and Kanchan will raise it.</p>
    <input placeholder="your email" value={email} onChange={e=>setEmail(e.target.value)}/>
    <input placeholder="a note (optional)" value={note} onChange={e=>setNote(e.target.value)}/>
    <button onClick={go}>Request wake-up</button>
  </div>;
}

/* ─────────────────────────────── CV ──────────────────────────────────────── */
function CV(){
  return <div className="cvpaper">
    <div className="cv-name">KANCHAN GHOSH</div>
    <div className="cv-role">AI Researcher · Developer · Builder</div>
    <div className="cv-contact">Leeds, UK · Remote worldwide · kanchan@ikanchan.com · www.loveuad.com</div>
    <div className="cv-rule"/>
    <div className="cv-h">Profile</div>
    <p className="cv-p">Independent AI researcher and full-stack developer who goes from research paper to shipped product to paying customer. Production LLM &amp; RAG systems across banking, healthcare and education. Currently a stay-at-home dad, seeking remote AI-engineering work.</p>
    <div className="cv-h">Selected Work</div>
    <p className="cv-p"><b>LMA EDGE</b> — AI document-intelligence for syndicated-loan review.<br/><b>WritenDraw</b> — multi-agent AI assessment; first paying UK customer.<br/><b>CareCircle</b> — zero-knowledge health notifications; NHS Propel selected.<br/><b>AiwithAI</b> — browser AI-engineering education on a budget Android.</p>
    <div className="cv-h">Research</div>
    <p className="cv-p">Artificial Education (Zenodo) · TrueSkills, AI-resistant assessment (SSRN, R&amp;R at BJET) · Privacy-First Healthcare (Zenodo) · MPS guardrail-degradation safety research.</p>
    <div className="cv-h">Experience &amp; Education</div>
    <p className="cv-p">Founder, LOVEUAD LTD · 9 years banking (TCS, State Bank of Mysore) · MBA (Finance &amp; Marketing, top of class) · B.Pharm, Jadavpur University · Google Cloud certified.</p>
    <div className="cv-foot">Curriculum Vitae</div>
  </div>;
}

/* ─────────────────────────────── APP ─────────────────────────────────────── */
export default function App(){
  const [phase,setPhase]     = useState("reading");
  const [messages,setMsg]    = useState([]);
  const [input,setInput]     = useState("");
  const [loading,setLoad]    = useState(false);
  const [active,setActive]   = useState(null);
  const [voiceOn,setVoice]   = useState(true);
  const [listening,setListen]= useState(false);
  const endRef  = useRef(null);
  const voiceRef= useRef(true);
  const audioRef= useRef(null);
  const recogRef= useRef(null);
  useEffect(()=>{ voiceRef.current=voiceOn; },[voiceOn]);
  useEffect(()=>{ endRef.current?.scrollIntoView({behavior:"smooth"}); },[messages,loading]);

  // random 5s entrance
  useEffect(()=>{
    const t = setTimeout(()=>{ setPhase("arrived"); }, 5000);
    return ()=>clearTimeout(t);
  },[]);

  async function speak(text){
    if(!voiceRef.current||!text) return;
    try{
      const res = await fetch("/api/tts",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text})});
      if(res.status===200){ const d=await res.json(); if(d?.audio){ if(audioRef.current) audioRef.current.pause(); const a=new Audio(d.audio); audioRef.current=a; a.play().catch(()=>{}); return; } }
    }catch(e){}
  }

  function ringBell(){ setPhase("talking"); setTimeout(()=>speak(GREET),200); }

  function toggleMic(){
    if(listening){ recogRef.current?.stop(); setListen(false); return; }
    const SR=window.SpeechRecognition||window.webkitSpeechRecognition;
    if(!SR) return;
    const r=new SR(); r.lang="en-GB"; r.interimResults=false;
    r.onresult=(e)=>{ const t=e.results[0][0].transcript; if(t.trim()) send(t.trim()); setListen(false); };
    r.onerror=()=>setListen(false); r.onend=()=>setListen(false);
    recogRef.current=r;
    if(audioRef.current) try{audioRef.current.pause();}catch(e){}
    r.start(); setListen(true);
  }

  async function ask(history){
    const res=await fetch("/api/chat",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({messages:history})});
    const d=await res.json(); return d.reply||"";
  }

  async function send(text){
    const t=(text||"").trim(); if(!t||loading) return;
    const next=[...messages,{role:"user",content:t}];
    setMsg(next); setInput(""); setLoad(true);
    try{
      const raw=await ask(next);
      const m=raw.match(/\[\[project:([a-z0-9-]+)\]\]/i);
      if(m&&PROJECTS.some(p=>p.id===m[1])) setActive(m[1]);
      const clean=raw.replace(/\[\[project:[a-z0-9-]+\]\]/gi,"").trim()||"Quite so.";
      setMsg([...next,{role:"assistant",content:clean}]); speak(clean);
    }catch(e){ setMsg([...next,{role:"assistant",content:"Forgive me — the line went quiet. Do try again."}]); }
    setLoad(false);
  }

  const proj=PROJECTS.find(p=>p.id===active);

  return (
    <div className="app">
      <style>{CSS}</style>
      <h1 className="ttl">CV — Kanchan Ghosh</h1>

      <div className="main">
        {phase!=="talking" ? (
          <div className="cvwrap">
            <CV/>
            {phase==="arrived" && (
              <div className="emerge">
                <div className="bubble">Hello, sir.</div>
                <img className="popimg" src={BOW_IMG} alt="Bertie"/>
                <button className="ringbtn" onClick={ringBell}>🔔 Ring for him</button>
              </div>
            )}
          </div>
        ) : (
          <div className="hall">
            <div className="bcol">
              <div className="bplate"><b>Bertie</b><span>Keeper of the résumé</span></div>
              <button className="voicetgl" onClick={()=>{ if(voiceOn&&audioRef.current) try{audioRef.current.pause();}catch(e){} setVoice(!voiceOn); }}>
                {voiceOn?"🔊":"🔇"}
              </button>
              <img className="bidleimg" src={IDLE_IMG} alt="Bertie"/>
            </div>

            <div className="ccol">
              <div className="chead"><span className="dot"/> Bertie <small>at your service</small></div>
              <div className="msgs">
                <div className="row"><div className="bub a">{GREET}</div></div>
                {messages.map((m,i)=>(
                  <div key={i} className={"row"+(m.role==="user"?" u":"")}>
                    <div className={"bub"+(m.role==="user"?" u":" a")}>{m.content}</div>
                  </div>
                ))}
                {loading&&<div className="row"><div className="bub a"><span className="dots"><i/><i/><i/></span></div></div>}
                <div ref={endRef}/>
              </div>
              <div className="chips">
                {PROJECTS.map(p=><button key={p.id} className="chip" onClick={()=>send("Tell me about "+p.name+".")}>{p.name}</button>)}
                <button className="chip" onClick={()=>send("Is Kanchan available for work?")}>Available?</button>
              </div>
              <div className="inbar">
                <button className={"micbtn"+(listening?" on":"")} onClick={toggleMic} title={listening?"Stop":"Speak"}>🎙</button>
                <input value={input} placeholder={listening?"Listening…":"Ask Bertie…"}
                  onChange={e=>setInput(e.target.value)}
                  onKeyDown={e=>{ if(e.key==="Enter") send(input); }}/>
                <button className="sendbtn" disabled={loading||!input.trim()} onClick={()=>send(input)}>Send</button>
              </div>
            </div>
          </div>
        )}
      </div>

      {proj&&(
        <div className="backdrop" onClick={()=>setActive(null)}>
          <div className="card" onClick={e=>e.stopPropagation()}>
            <button className="cx" onClick={()=>setActive(null)}>×</button>
            {proj.video
              ?<div className="vid"><iframe src={"https://www.youtube.com/embed/"+proj.video} title={proj.name} allow="accelerometer;autoplay;clipboard-write;encrypted-media;gyroscope;picture-in-picture" allowFullScreen/></div>
              :<div className="novid">▶ demo video — link to be added</div>}
            <div className="body">
              <h3>{proj.name}</h3>
              <div className="meta">{proj.cat} · {proj.year}</div>
              <ul>{proj.points.map((pt,i)=><li key={i}>{pt}</li>)}</ul>
              <div className="lks">
                {proj.video&&<a className="lk" href={"https://youtu.be/"+proj.video} target="_blank" rel="noreferrer">▶ Watch on YouTube</a>}
              </div>
              {proj.link&&<WakeBox project={proj.name}/>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
