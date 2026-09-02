'use strict';
const http=require('http');
const fs=require('fs');
const path=require('path');
const crypto=require('crypto');

// Tiny .env loader so the MVP has no external npm dependencies.
const envPath=path.join(__dirname,'.env');
if(fs.existsSync(envPath)){
  for(const line of fs.readFileSync(envPath,'utf8').split(/\r?\n/)){
    const t=line.trim(); if(!t||t.startsWith('#')||!t.includes('=')) continue;
    const i=t.indexOf('='); const k=t.slice(0,i).trim(); let v=t.slice(i+1).trim();
    if((v.startsWith('"')&&v.endsWith('"'))||(v.startsWith("'")&&v.endsWith("'"))) v=v.slice(1,-1);
    if(!(k in process.env)) process.env[k]=v;
  }
}

const PORT=Number(process.env.PORT||3000);
const BOT_TOKEN=process.env.BOT_TOKEN||'';
const CHANNEL_ID=process.env.CHANNEL_ID||''; // @channel_username or -100...
const OWNER_CHAT_ID=process.env.OWNER_CHAT_ID||''; // where applications are delivered
const ROOT=__dirname;
const MAX_AGE_SEC=Number(process.env.INIT_DATA_MAX_AGE_SEC||86400);
const ANALYTICS_PATH=path.join(ROOT,'analytics.jsonl');

const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.svg':'image/svg+xml','.webp':'image/webp','.ico':'image/x-icon'};

function json(res,code,obj){res.writeHead(code,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(obj));}
function readBody(req){return new Promise((resolve,reject)=>{let data='';req.on('data',c=>{data+=c;if(data.length>200000){reject(new Error('body_too_large'));req.destroy();}});req.on('end',()=>resolve(data));req.on('error',reject)});}
function safeEqualHex(a,b){try{const ab=Buffer.from(a,'hex'),bb=Buffer.from(b,'hex');return ab.length===bb.length&&crypto.timingSafeEqual(ab,bb)}catch{return false}}
function esc(s=''){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}

function validateInitData(initData){
  if(!BOT_TOKEN) throw new Error('BOT_TOKEN is not configured');
  const p=new URLSearchParams(initData);const hash=p.get('hash');if(!hash)return null;p.delete('hash');
  const dataCheck=[...p.entries()].sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>`${k}=${v}`).join('\n');
  const secret=crypto.createHmac('sha256','WebAppData').update(BOT_TOKEN).digest();
  const expected=crypto.createHmac('sha256',secret).update(dataCheck).digest('hex');
  if(!safeEqualHex(hash,expected))return null;
  const authDate=Number(p.get('auth_date')||0);if(!authDate||Math.abs(Date.now()/1000-authDate)>MAX_AGE_SEC)return null;
  try{return JSON.parse(p.get('user')||'null')}catch{return null}
}

async function isChannelMember(userId){
  if(!BOT_TOKEN||!CHANNEL_ID)throw new Error('BOT_TOKEN / CHANNEL_ID not configured');
  const url=`https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(CHANNEL_ID)}&user_id=${encodeURIComponent(userId)}`;
  const r=await fetch(url);const data=await r.json();if(!data.ok)return false;
  const m=data.result||{};return ['creator','administrator','member'].includes(m.status)||(m.status==='restricted'&&m.is_member===true);
}

async function telegram(method,payload){
  if(!BOT_TOKEN)throw new Error('BOT_TOKEN is not configured');
  const r=await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const data=await r.json();if(!data.ok)throw new Error(data.description||'telegram_api_error');return data.result;
}

async function verifiedUser(body,requireMembership=true){
  const user=validateInitData(body.initData||'');if(!user?.id)return {error:'invalid_init_data'};
  if(requireMembership && !(await isChannelMember(user.id)))return {error:'not_member',user};
  return {user};
}

async function apiAccess(req,res){
  try{const body=JSON.parse(await readBody(req)||'{}');const v=await verifiedUser(body,false);if(v.error)return json(res,401,{allowed:false,error:v.error});const allowed=await isChannelMember(v.user.id);return json(res,200,{allowed,user:{id:v.user.id,first_name:v.user.first_name||'',username:v.user.username||''}});}catch(e){console.error(e);return json(res,500,{allowed:false,error:'access_check_failed'});}
}

async function apiEvent(req,res){
  try{const body=JSON.parse(await readBody(req)||'{}');const v=await verifiedUser(body,true);if(v.error)return json(res,v.error==='not_member'?403:401,{ok:false,error:v.error});const event=String(body.event||'').slice(0,64);if(!event)return json(res,400,{ok:false,error:'event_required'});const row={ts:new Date().toISOString(),userId:v.user.id,username:v.user.username||'',event,meta:body.meta&&typeof body.meta==='object'?body.meta:{}};fs.appendFile(ANALYTICS_PATH,JSON.stringify(row)+'\n',()=>{});return json(res,200,{ok:true});}catch(e){console.error(e);return json(res,500,{ok:false,error:'event_failed'});}
}

async function apiLead(req,res){
  try{
    if(!OWNER_CHAT_ID)return json(res,503,{ok:false,error:'owner_chat_not_configured'});
    const body=JSON.parse(await readBody(req)||'{}');const v=await verifiedUser(body,true);if(v.error)return json(res,v.error==='not_member'?403:401,{ok:false,error:v.error});
    const d=body.diagnostic||{};
    const overall=Math.max(0,Math.min(100,Number(d.overall)||0));
    const weak=String(d.weak||'').slice(0,40);
    const weakScore=Math.max(0,Math.min(100,Number(d.weakScore)||0));
    const rawPct=d.pct&&typeof d.pct==='object'?d.pct:{};
    const names={context:'Цель и контекст',client:'Клиент',competition:'Конкуренты и альтернативы',journey:'Путь клиента',architecture:'Система и MVP',ai:'Контекст для AI'};
    const pct={}; for(const k of Object.keys(names)) pct[k]=Math.max(0,Math.min(100,Number(rawPct[k])||0));
    const fullName=[v.user.first_name,v.user.last_name].filter(Boolean).join(' ')||'Без имени';
    const username=v.user.username?`@${v.user.username}`:'username не указан';
    const userLink=v.user.username?`https://t.me/${encodeURIComponent(v.user.username)}`:`tg://user?id=${v.user.id}`;
    const map=Object.keys(names).map(k=>`• ${names[k]}: <b>${pct[k]}%</b>`).join('\n');
    const text=`🟣 <b>НОВАЯ ЗАЯВКА · BUSINESS LAB</b>

👤 <a href="${userLink}">${esc(fullName)}</a>
${esc(username)} · ID <code>${v.user.id}</code>

<b>Результат диагностики</b>
Общая ясность: <b>${overall}%</b>
Главная точка роста: <b>${esc(names[weak]||weak||'не определено')} · ${weakScore}%</b>

${map}

<b>Группа:</b> старт 5 сентября · 10 человек · 7 000 ₽

👉 Нажми на имя сверху, чтобы открыть диалог.`;
    await telegram('sendMessage',{chat_id:OWNER_CHAT_ID,text,parse_mode:'HTML',disable_web_page_preview:true});
    fs.appendFile(ANALYTICS_PATH,JSON.stringify({ts:new Date().toISOString(),userId:v.user.id,username:v.user.username||'',event:'lead',meta:{overall,weak,weakScore}})+'\n',()=>{});
    return json(res,200,{ok:true});
  }catch(e){console.error(e);return json(res,500,{ok:false,error:'lead_failed'});}
}

function staticFile(req,res){
  let urlPath=new URL(req.url,'http://localhost').pathname;if(urlPath==='/')urlPath='/index.html';
  const target=path.normalize(path.join(ROOT,urlPath));if(!target.startsWith(ROOT))return json(res,403,{error:'forbidden'});
  fs.stat(target,(err,st)=>{if(err||!st.isFile()){res.writeHead(404);return res.end('Not found')}const ext=path.extname(target).toLowerCase();res.writeHead(200,{'Content-Type':MIME[ext]||'application/octet-stream','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cache-Control':ext==='.html'?'no-cache':'public, max-age=3600'});if(req.method==='HEAD')return res.end();fs.createReadStream(target).pipe(res)});
}

function serveIndex(req,res){
  const target=path.join(ROOT,'index.html');
  fs.readFile(target,(err,data)=>{
    if(err){
      console.error('index.html read error:',err);
      res.writeHead(500,{'Content-Type':'text/plain; charset=utf-8'});
      return res.end('App file is missing');
    }
    res.writeHead(200,{
      'Content-Type':'text/html; charset=utf-8',
      'Cache-Control':'no-cache',
      'X-Content-Type-Options':'nosniff',
      'Referrer-Policy':'no-referrer'
    });
    if(req.method==='HEAD')return res.end();
    res.end(data);
  });
}

const server=http.createServer(async(req,res)=>{
  const pathname=new URL(req.url,'http://localhost').pathname;
  if(req.method==='POST'&&pathname==='/api/access')return apiAccess(req,res);
  if(req.method==='POST'&&pathname==='/api/event')return apiEvent(req,res);
  if(req.method==='POST'&&pathname==='/api/lead')return apiLead(req,res);
  if((req.method==='GET'||req.method==='HEAD')&&pathname==='/health')return json(res,200,{ok:true});
  if((req.method==='GET'||req.method==='HEAD')&&(pathname==='/'||pathname==='/index.html'))return serveIndex(req,res);
  if(req.method==='GET'||req.method==='HEAD'){
    // The MVP is a single-page app. Try a real static file first; if the URL
    // is a Telegram launch route or another client-side route, fall back to index.html.
    let target=path.normalize(path.join(ROOT,pathname));
    if(target.startsWith(ROOT)){
      try{
        const st=fs.statSync(target);
        if(st.isFile())return staticFile(req,res);
      }catch{}
    }
    return serveIndex(req,res);
  }
  res.writeHead(405);res.end('Method not allowed');
});
server.listen(PORT,'0.0.0.0',()=>console.log(`TORIYA NOVA Business Lab listening on ${PORT}`));
