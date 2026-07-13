import React, { useState, useEffect, useRef } from "react";
import IDLE_IMG from "./butler-idle.png";
import BOW_IMG from "./butler-bow.png";

// video = YouTube id (swap ids to re-map).  link = public url (blank = none).
const PROJECTS = [
  { id:"lma-edge", name:"LMA EDGE", cat:"Banking", year:"2026", video:"ujEeGC7_2jw", link:"",
    blurb:"AI document-intelligence for syndicated-loan review.",
    points:[
      "Audits LMA Deal Bibles (500+ pages) for bank VPs, legal and compliance teams.",
      "Local PII neutralisation — sensitive deal terms never leave the machine before any LLM call.",
      "RAG gap-reports with citations, shipped as a zero-infrastructure Windows EXE." ]},
  { id:"writendraw", name:"WritenDraw", cat:"EdTech", year:"2025", video:"Q1MO2xNM3UY", link:"https://writendraw.com/",
    blurb:"Chat-based AI workplace-simulation assessment.",
    points:[
      "Multi-agent evaluation with full audit trails on Google Cloud Run + Gemini.",
      "First paying UK customer, in construction; piloted at a London FE college.",
      "Built on the TrueSkills anti-cheating research." ]},
  { id:"trueskills", name:"TrueSkills", cat:"Research · EdTech", year:"2025", video:"7WOP9gosheA", link:"https://trueskills.uk/",
    blurb:"AI-resistant assessment through personalised understanding.",
    points:[
      "Generates questions from a student's own submission to defeat GenAI cheating.",
      "Adaptive testing, 100 concurrent students, dynamic difficulty.",
      "Paper under revise-and-resubmit at BJET." ]},
  { id:"carecircle", name:"CareCircle", cat:"Healthcare", year:"2025", video:"2c3ULCUq8-0", link:"https://www.carecircle.top/",
    blurb:"Zero-knowledge health notifications.",
    points:[
      "SHA-256 codes replace login — no name, email or mobile number.",
      "Eliminates the data-breach surface entirely; privacy by design.",
      "Selected for the NHS Propel HealthTech Accelerator." ]},
  { id:"aiwithai", name:"AiwithAI", cat:"EdTech", year:"2026", video:"3ANmfbwMti4", link:"https://aiwithai.online/",
    blurb:"Browser-based AI-engineering education for learners without computers.",
    points:[
      "Validated under Rs.400 per learner on a budget Android phone.",
      "Designed for low-infrastructure environments.",
      "Published as 'Artificial Education' on Zenodo." ]},
  { id:"mps-safety", name:"MPS Safety Research", cat:"AI Safety", year:"2026", video:"hWUkVUQeiys", link:"",
    blurb:"Guardrail degradation under multi-prompt conditions.",
    points:[
      "Stress-tested suicide safe-messaging guardrails across six LLMs, four attack vectors.",
      "Finding: failure rates rise with node depth — depth compounded vulnerability.",
      "Responsible disclosure filed with OpenAI and Google." ]},
  { id:"ai-films", name:"AI Films", cat:"Creative", year:"2026", video:"f8vnUIgTNPc", link:"",
    blurb:"Signal Lost, THREE and Poriyayi.",
    points:[
      "Director of AI-generated short films — script to screen, fully AI-powered.",
      "Selected for Africa AI Creativity Week & Awards 2026, Marrakech.",
      "Also a published Bengali novelist and AI music-album maker." ]},
  { id:"dokanbajar", name:"DokanBajar", cat:"Commerce", year:"2025", video:"9hATQ3_eN2s", link:"",
    blurb:"Hyperlocal marketplace for Kolkata fish & vegetable markets.",
    points:[
      "Flutter + Flask + Supabase, Gemini OCR for listings.",
      "Built for real neighbourhood vendors, not abstract users.",
      "Part of a wider set of commerce demos (Sonamati, Leeds City Connect)." ]},
  { id:"mymomstories", name:"My Mom's Stories", cat:"Multilingual", year:"2025", video:"", link:"",
    blurb:"Heritage-language reading app across 13 languages.",
    points:[
      "Flask + PostgreSQL + Gemini TTS.",
      "Built to keep diaspora children connected to a mother tongue.",
      "Draws on 2M+ words of English-Bengali translation experience." ]},
  { id:"trione", name:"TRIONE DIVION Avatar", cat:"Client Work", year:"2025", video:"", link:"",
    blurb:"Digital-twin / talking-avatar platform for a Serbian client.",
    points:[
      "LiveAvatar + ElevenLabs + LiveKit.",
      "Real-time speaking avatar for client Petar.",
      "Commissioned commercial engagement." ]},
];

const HELLO_LINE = "Oh - hello, sir. I didn't hear you come in.";
const GREETING =
  "You rang? Splendid. You came for a CV, I take it - I'm afraid the dull paper one stays in my drawer, but I keep everything up here. Ask me anything about Kanchan: his projects, his papers, whether he's free for work.";

const CSS = `
:root{--paper:#EAE1CE;--paper2:#DFD3B8;--ink:#2B2620;--ink2:#6B6152;--ox:#7C2B2B;--ox2:#9B3A3A;--blush:#F1DAD6;--room:#241f1b;--gold:#C6A24A;}
*{box-sizing:border-box}
.wrap{font-family:'Segoe UI',system-ui,sans-serif;color:var(--ink);background:radial-gradient(1200px 700px at 50% -10%,#3a322b 0%,#211d19 55%,#171310 100%);height:100vh;height:100dvh;display:flex;flex-direction:column;overflow:hidden;padding:14px 14px}
.title{text-align:center;color:#F3ECDD;font-family:Georgia,serif;font-size:22px;font-weight:600;margin:6px 0 14px;flex:0 0 auto}
.stagearea{flex:1;min-height:0;display:flex;justify-content:center;overflow:hidden}
.desk{position:relative;width:100%;max-width:520px;height:100%;margin:0 auto;display:flex;align-items:center;justify-content:center;overflow-y:auto}
.desk.arr .cvpaper{filter:brightness(.82)}
.cvpaper{width:460px;max-width:92vw;background:linear-gradient(180deg,rgba(255,255,255,.05),rgba(0,0,0,.04)),var(--paper);border:1px solid #cbbd9f;border-radius:6px;padding:30px 30px 24px;position:relative;z-index:1;box-shadow:0 26px 54px rgba(0,0,0,.5)}
.cv-name{font-family:Georgia,serif;font-size:26px;font-weight:700;margin:0}
.cv-role{color:var(--ox);font-weight:600;font-size:12.5px;letter-spacing:.03em;margin:2px 0 6px}
.cv-contact{font-size:11.5px;color:var(--ink2);margin-bottom:12px}
.cv-rule{height:2px;background:var(--ox);opacity:.6;margin:8px 0 14px}
.cv-h{font-size:10.5px;letter-spacing:.2em;text-transform:uppercase;color:var(--ink2);font-weight:700;margin:16px 0 6px}
.cv-p{font-size:12.7px;line-height:1.6;margin:0}.cv-p b{color:var(--ink)}
.cv-foot{margin-top:16px;border-top:1px solid #cdbf9f;padding-top:8px;text-align:center;font-family:Georgia,serif;font-style:italic;color:var(--ink2);font-size:11.5px}
.emerge{position:absolute;top:50%;left:50%;z-index:5;display:flex;flex-direction:column;align-items:center;transform:translate(-50%,-50%);animation:emerge .72s cubic-bezier(.34,1.56,.64,1) both}
@keyframes emerge{0%{opacity:0;transform:translate(-50%,-42%) scale(.38)}60%{opacity:1;transform:translate(-50%,-53%) scale(1.05)}100%{opacity:1;transform:translate(-50%,-50%) scale(1)}}
.hello{background:#fff;border:1px solid #cbbd9f;border-radius:14px;padding:8px 15px;font-family:Georgia,serif;font-size:14px;position:relative;margin-bottom:-4px;box-shadow:0 10px 20px rgba(0,0,0,.28)}
.hello:after{content:'';position:absolute;bottom:-8px;left:26px;border:8px solid transparent;border-top-color:#fff}
.popbutler{height:360px;max-height:52vh;filter:drop-shadow(0 24px 28px rgba(0,0,0,.6))}
.ring{margin-top:14px;background:var(--ox);color:#fff;border:none;border-radius:999px;padding:12px 24px;font-size:14px;font-weight:600;letter-spacing:.02em;cursor:pointer;box-shadow:0 12px 24px rgba(0,0,0,.45)}
.ring:hover{background:var(--ox2)}
.hall{display:flex;gap:20px;width:100%;max-width:1000px;height:100%;margin:0 auto;align-items:stretch;min-height:0}
.stagecol{flex:0 0 300px;border-radius:14px;overflow:hidden;position:relative;height:100%;min-height:0;background:radial-gradient(300px 320px at 50% 74%,var(--blush) 0%,#5a4a44 46%,var(--room) 100%);display:flex;align-items:flex-end;justify-content:center;box-shadow:inset 0 0 70px rgba(0,0,0,.5)}
.butler-idle{height:92%;filter:drop-shadow(0 20px 22px rgba(0,0,0,.45));animation:sway 5.5s ease-in-out infinite}
@keyframes sway{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
.plate{position:absolute;top:14px;left:14px;background:rgba(20,16,13,.72);color:#F3ECDD;border:1px solid var(--gold);border-radius:8px;padding:6px 11px}
.plate b{display:block;font-family:Georgia,serif;font-size:14px}.plate span{font-size:10px;color:var(--gold);letter-spacing:.12em;text-transform:uppercase}
.voicebtn{position:absolute;top:14px;right:14px;background:rgba(20,16,13,.72);color:#F3ECDD;border:1px solid var(--gold);border-radius:8px;padding:6px 10px;font-size:12px;cursor:pointer}
.chatcol{flex:1;min-width:0;background:var(--paper);border:1px solid #cbbd9f;border-radius:14px;display:flex;flex-direction:column;overflow:hidden;height:100%;min-height:0}
.chead{background:linear-gradient(180deg,#33291f,#241d16);color:#F3ECDD;padding:14px 18px;font-family:Georgia,serif;display:flex;align-items:center;gap:10px}
.chead .dot{width:8px;height:8px;border-radius:50%;background:#7dd08e;box-shadow:0 0 8px #7dd08e}
.chead small{color:var(--gold);letter-spacing:.1em;text-transform:uppercase;font-size:10px;font-family:'Segoe UI',sans-serif;margin-left:auto}
.msgs{flex:1;overflow-y:auto;padding:18px;display:flex;flex-direction:column;gap:12px}
.row{display:flex}.row.u{justify-content:flex-end}
.bub{max-width:82%;padding:10px 14px;border-radius:14px;font-size:14px;line-height:1.5}
.bub.a{background:#fff;border:1px solid #d9cbac;border-bottom-left-radius:4px;color:var(--ink)}
.bub.u{background:var(--ox);color:#fff;border-bottom-right-radius:4px}
.think{display:inline-flex;gap:4px;align-items:center}
.think i{width:6px;height:6px;border-radius:50%;background:var(--ink2);animation:blink 1.2s infinite}
.think i:nth-child(2){animation-delay:.2s}.think i:nth-child(3){animation-delay:.4s}
@keyframes blink{0%,100%{opacity:.2}50%{opacity:1}}
.chips{display:flex;gap:7px;overflow-x:auto;padding:10px 14px;border-top:1px solid #d9cbac;background:var(--paper2)}
.chip{white-space:nowrap;background:#fff;border:1px solid #cdbf9f;border-radius:999px;padding:6px 12px;font-size:12px;color:var(--ink);cursor:pointer}
.chip:hover{background:var(--blush);border-color:var(--ox)}
.inbar{display:flex;gap:8px;padding:12px 14px;border-top:1px solid #d9cbac;background:var(--paper)}
.inbar input{flex:1;border:1px solid #cbbd9f;border-radius:10px;padding:11px 13px;font-size:14px;background:#fff;color:var(--ink);outline:none}
.inbar input:focus{border-color:var(--ox)}
.send{background:var(--ox);color:#fff;border:none;border-radius:10px;padding:0 18px;font-size:14px;font-weight:600;cursor:pointer}
.send:hover{background:var(--ox2)}.send:disabled{opacity:.5;cursor:default}
.backdrop{position:fixed;inset:0;background:rgba(20,15,12,.62);z-index:40;display:flex;align-items:center;justify-content:center;padding:18px}
.card{background:var(--paper);border:1px solid #c3b393;border-radius:16px;width:640px;max-width:100%;max-height:90vh;overflow-y:auto;box-shadow:0 30px 70px rgba(0,0,0,.5)}
.card .vid{position:relative;width:100%;aspect-ratio:16/9;background:#000;border-radius:16px 16px 0 0;overflow:hidden}
.card .vid iframe{position:absolute;inset:0;width:100%;height:100%;border:0}
.card .novid{aspect-ratio:16/9;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#33291f,#241d16);color:var(--gold);border-radius:16px 16px 0 0;font-size:13px}
.card .body{padding:20px 22px 24px}
.card .cx{position:absolute;top:12px;right:12px;z-index:2;background:rgba(20,15,12,.7);color:#fff;border:none;width:32px;height:32px;border-radius:50%;font-size:16px;cursor:pointer}
.card h3{font-family:Georgia,serif;font-size:22px;margin:0 0 3px}
.card .meta{color:var(--ox);font-size:12px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;margin-bottom:12px}
.card ul{margin:0 0 14px;padding-left:18px}.card li{font-size:14px;line-height:1.55;margin:6px 0}
.card .links{display:flex;gap:10px;flex-wrap:wrap}
.card .lnk{text-decoration:none;font-size:13px;font-weight:600;padding:9px 14px;border-radius:10px;border:1px solid var(--ox);color:var(--ox)}
.card .lnk.f{background:var(--ox);color:#fff}
@media(max-width:760px){.hall{flex-direction:column}.stagecol{flex:0 0 34vh;min-height:0}.chatcol{flex:1;min-height:0}}
@media (prefers-reduced-motion: reduce){.emerge{animation:none}.butler-idle{animation:none}}

.wake{margin-top:14px;background:#fff;border:1px solid #d9cbac;border-radius:12px;padding:12px 14px}
.wake-h{font-size:12.5px;color:var(--ink2);line-height:1.5;margin-bottom:10px}
.wake input{width:100%;border:1px solid #cbbd9f;border-radius:8px;padding:9px 11px;font-size:13px;margin-bottom:8px;background:#fff;color:var(--ink);outline:none}
.wake input:focus{border-color:var(--ox)}
.wake button{background:var(--ox);color:#fff;border:none;border-radius:8px;padding:9px 16px;font-size:13px;font-weight:600;cursor:pointer}
.wake button:hover{background:var(--ox2)}
.wake.ok{color:#2e6b3a;font-size:13px;font-weight:600;line-height:1.5}
`;

function CV(){
  return (
    <div className="cvpaper">
      <h2 className="cv-name">KANCHAN GHOSH</h2>
      <div className="cv-role">AI Researcher · Developer · Builder</div>
      <div className="cv-contact">Leeds, UK · Remote worldwide · kanchan@ikanchan.com · www.loveuad.com</div>
      <div className="cv-rule" />
      <div className="cv-h">Profile</div>
      <p className="cv-p">Independent AI researcher and full-stack developer who goes from research paper to shipped product to paying customer. Production LLM &amp; RAG systems across banking, healthcare and education. Currently a stay-at-home dad, seeking remote AI-engineering work.</p>
      <div className="cv-h">Selected Work</div>
      <p className="cv-p"><b>LMA EDGE</b> — AI document-intelligence for syndicated-loan review.<br/>
      <b>WritenDraw</b> — multi-agent AI assessment; first paying UK customer.<br/>
      <b>CareCircle</b> — zero-knowledge health notifications; selected for NHS Propel.<br/>
      <b>AiwithAI</b> — browser AI-engineering education on a budget Android.</p>
      <div className="cv-h">Research</div>
      <p className="cv-p">Artificial Education (Zenodo) · TrueSkills, AI-resistant assessment (SSRN, R&amp;R at BJET) · Privacy-First Healthcare (Zenodo) · MPS guardrail-degradation safety research.</p>
      <div className="cv-h">Experience &amp; Education</div>
      <p className="cv-p">Founder, LOVEUAD LTD · 9 years banking (TCS, State Bank of Mysore) · MBA (Finance &amp; Marketing) · B.Pharm, Jadavpur University · Google Cloud certified.</p>
      <div className="cv-foot">Curriculum Vitae</div>
    </div>
  );
}

function WakeBox({project}){
  const [email,setEmail]=useState("");
  const [note,setNote]=useState("");
  const [sent,setSent]=useState(false);
  async function submit(){
    if(!email.trim()) return;
    try{ await fetch("/api/wake",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({project,email,note})}); }catch(e){}
    setSent(true);
  }
  if(sent) return <div className="wake ok">✓ Request sent — Kanchan will raise the site shortly.</div>;
  return (
    <div className="wake">
      <div className="wake-h">⏸ This live site is hibernated to keep costs down. Want to see it running? Leave your email and Kanchan will raise it.</div>
      <input placeholder="your email" value={email} onChange={e=>setEmail(e.target.value)} />
      <input placeholder="a note (optional)" value={note} onChange={e=>setNote(e.target.value)} />
      <button onClick={submit}>Request wake-up</button>
    </div>
  );
}

export default function App(){
  const [phase,setPhase]   = useState("reading");   // reading | arrived | talking
  const [messages,setMsg]  = useState([]);
  const [input,setInput]   = useState("");
  const [loading,setLoad]  = useState(false);
  const [active,setActive] = useState(null);
  const [voiceOn,setVoice] = useState(true);
  const endRef   = useRef(null);
  const voiceRef = useRef(true);
  const audioRef = useRef(null);
  useEffect(()=>{ voiceRef.current = voiceOn; },[voiceOn]);

  useEffect(()=>{
    const delay = 5000;             // random 5-20s surprise
    const t = setTimeout(()=>{ setPhase("arrived"); speak(HELLO_LINE); }, delay);
    return ()=>clearTimeout(t);
  },[]);
  useEffect(()=>{ endRef.current && endRef.current.scrollIntoView({behavior:"smooth"}); },[messages,loading]);



  // Gemini TTS via backend. No browser fallback — paid voice only.
  async function speak(text){
    if(!voiceRef.current || !text) return;
    try{
      const res = await fetch("/api/tts",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text})});
      if(res.status===200){
        const d = await res.json();
        if(d && d.audio){
          if(audioRef.current){ audioRef.current.pause(); }
          const a = new Audio(d.audio); audioRef.current = a;
          a.play().catch(()=>{});
        }
      }
    }catch(e){}
  }

  function ringBell(){ setPhase("talking"); setTimeout(()=>speak(GREETING),200); }

  async function ask(history){
    const res = await fetch("/api/chat",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({messages:history})});
    const d = await res.json();
    return d.reply || "";
  }

  async function send(text){
    const t = (text||"").trim();
    if(!t || loading) return;
    const next = [...messages,{role:"user",content:t}];
    setMsg(next); setInput(""); setLoad(true);
    try{
      const raw = await ask(next);
      const m = raw.match(/\[\[project:([a-z0-9-]+)\]\]/i);
      if(m && PROJECTS.some(p=>p.id===m[1])) setActive(m[1]);
      const clean = raw.replace(/\[\[project:[a-z0-9-]+\]\]/gi,"").trim() || "Quite so.";
      setMsg([...next,{role:"assistant",content:clean}]);
      speak(clean);
    }catch(e){
      setMsg([...next,{role:"assistant",content:"Forgive me - the line to my study went quiet. Do try again."}]);
    }
    setLoad(false);
  }

  const proj = PROJECTS.find(p=>p.id===active);

  return (
    <div className="wrap">
      <style>{CSS}</style>
      <h1 className="title">CV — Kanchan Ghosh</h1>

      <div className="stagearea">
      {phase!=="talking" ? (
        <div className={"desk"+(phase==="arrived"?" arr":"")}>
          <CV/>
          {phase==="arrived" && (
            <div className="emerge">
              <div className="hello">Hello, sir.</div>
              <img className="popbutler" src={BOW_IMG} alt="Bertie the butler" />
              <button className="ring" onClick={ringBell}>🔔 Ring for him</button>
            </div>
          )}
        </div>
      ) : (
        <div className="hall">
          <div className="stagecol">
            <div className="plate"><b>Bertie</b><span>Keeper of the résumé</span></div>
            <button className="voicebtn" onClick={()=>{ if(voiceOn && audioRef.current){try{audioRef.current.pause();}catch(e){}} setVoice(!voiceOn); }}>
              {voiceOn?"🔊 Voice on":"🔇 Voice off"}
            </button>
            <img className="butler-idle" src={IDLE_IMG} alt="Bertie the butler" />
          </div>
          <div className="chatcol">
            <div className="chead"><span className="dot"/> Bertie <small>at your service</small></div>
            <div className="msgs">
              <div className="row"><div className="bub a">{GREETING}</div></div>
              {messages.map((m,i)=>(
                <div key={i} className={"row "+(m.role==="user"?"u":"")}>
                  <div className={"bub "+(m.role==="user"?"u":"a")}>{m.content}</div>
                </div>
              ))}
              {loading && <div className="row"><div className="bub a"><span className="think"><i/><i/><i/></span></div></div>}
              <div ref={endRef}/>
            </div>
            <div className="chips">
              {PROJECTS.map(p=>(
                <button key={p.id} className="chip" onClick={()=>send("Tell me about "+p.name+".")}>{p.name}</button>
              ))}
              <button className="chip" onClick={()=>send("Is Kanchan available for work?")}>Is he available?</button>
            </div>
            <div className="inbar">
              <input value={input} placeholder="Ask Bertie anything…"
                onChange={e=>setInput(e.target.value)}
                onKeyDown={e=>{ if(e.key==="Enter") send(input); }} />
              <button className="send" disabled={loading||!input.trim()} onClick={()=>send(input)}>Send</button>
            </div>
          </div>
        </div>
      )}
      </div>

      {proj && (
        <div className="backdrop" onClick={()=>setActive(null)}>
          <div className="card" onClick={e=>e.stopPropagation()}>
            <button className="cx" onClick={()=>setActive(null)}>×</button>
            {proj.video
              ? <div className="vid"><iframe src={"https://www.youtube.com/embed/"+proj.video}
                    title={proj.name} allow="accelerometer;autoplay;clipboard-write;encrypted-media;gyroscope;picture-in-picture" allowFullScreen/></div>
              : <div className="novid">▶ demo video — link to be added</div>}
            <div className="body">
              <h3>{proj.name}</h3>
              <div className="meta">{proj.cat} · {proj.year}</div>
              <ul>{proj.points.map((pt,i)=><li key={i}>{pt}</li>)}</ul>
              <div className="links">
                {proj.video && <a className="lnk" href={"https://youtu.be/"+proj.video} target="_blank" rel="noreferrer">▶ Watch on YouTube</a>}
              </div>
              {proj.link && <WakeBox project={proj.name}/>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
