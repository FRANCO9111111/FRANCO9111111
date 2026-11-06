'use strict';
// Lagos Close backend. Zero npm dependencies. Node >= 22.5 (uses node:sqlite).
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),zlib=require('zlib');
const {DatabaseSync}=require('node:sqlite');
const PORT=+process.env.PORT||8080,ROOT=path.join(__dirname,'..'),DB_FILE=process.env.DB_FILE||path.join(__dirname,'lagos.db'),ADMIN_TOKEN=process.env.ADMIN_TOKEN||'';
const db=new DatabaseSync(DB_FILE);
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,salt TEXT NOT NULL,hash TEXT NOT NULL,username TEXT UNIQUE COLLATE NOCASE,gender TEXT,character_id TEXT DEFAULT 'default',setup_done INTEGER DEFAULT 0,created INTEGER);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS progress(user_id INTEGER PRIMARY KEY,data TEXT NOT NULL,updated INTEGER);
CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY,json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS entitlements(user_id INTEGER,character_id TEXT,payment_ref TEXT NOT NULL,verified_at INTEGER,PRIMARY KEY(user_id,character_id));`);
const seed=JSON.parse(fs.readFileSync(path.join(__dirname,'seed-config.json'),'utf8'));
for(const k of Object.keys(seed)){ if(!db.prepare('SELECT 1 FROM config WHERE key=?').get(k)) db.prepare('INSERT INTO config(key,json) VALUES(?,?)').run(k,JSON.stringify(seed[k])); }
const cfgGet=k=>{const r=db.prepare('SELECT json FROM config WHERE key=?').get(k);return r?JSON.parse(r.json):null};
const cfgAll=()=>{const o={};for(const r of db.prepare('SELECT key,json FROM config').all())o[r.key]=JSON.parse(r.json);return o};
const now=()=>Date.now(),DAY=864e5;
const hashPw=(pw,salt)=>crypto.scryptSync(pw,salt,64).toString('hex');
const J=(res,code,obj)=>{const b=JSON.stringify(obj);res.writeHead(code,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(b)};
const fail=(res,code,msg)=>J(res,code,{ok:false,error:msg});
const EMAIL=/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/,UNAME=/^[A-Za-z0-9_]{3,16}$/;
const RESERVED=new Set(['admin','moderator','system','police','officer','npc','tunde','chioma','kemi']);
function body(req){return new Promise((ok,no)=>{let n=0;const c=[];req.on('data',d=>{n+=d.length;if(n>400e3){no(new Error('too large'));req.destroy()}else c.push(d)});req.on('end',()=>{try{ok(c.length?JSON.parse(Buffer.concat(c).toString()):{})}catch(e){no(new Error('bad json'))}});req.on('error',no)})}
// ---- rate limit (per ip, login/register) ----
const hits=new Map();function limited(ip,max=20,win=60e3){const t=now(),a=(hits.get(ip)||[]).filter(x=>t-x<win);a.push(t);hits.set(ip,a);return a.length>max}
setInterval(()=>{const t=now();for(const[k,a]of hits){const f=a.filter(x=>t-x<60e3);f.length?hits.set(k,f):hits.delete(k)}db.prepare('DELETE FROM sessions WHERE expires<?').run(t)},60e3).unref();
// ---- auth ----
function newSession(uid){const token=crypto.randomBytes(32).toString('hex');db.prepare('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)').run(token,uid,now()+30*DAY);return token}
function userByToken(tok){if(!tok)return null;const s=db.prepare('SELECT user_id,expires FROM sessions WHERE token=?').get(tok);if(!s||s.expires<now())return null;return db.prepare('SELECT * FROM users WHERE id=?').get(s.user_id)}
const tokOf=req=>{const h=req.headers.authorization||'';return h.startsWith('Bearer ')?h.slice(7):null};
const pub=u=>({email:u.email,username:u.username,gender:u.gender,characterId:u.character_id,setupDone:!!u.setup_done});
const owned=uid=>db.prepare('SELECT character_id FROM entitlements WHERE user_id=?').all(uid).map(r=>r.character_id);
const getProg=uid=>{const r=db.prepare('SELECT data FROM progress WHERE user_id=?').get(uid);return r?JSON.parse(r.data):null};
const putProg=(uid,d)=>db.prepare('INSERT INTO progress(user_id,data,updated) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET data=excluded.data,updated=excluded.updated').run(uid,JSON.stringify(d),now());
const START_MONEY=50000;
function usernameCheck(u,uid){if(typeof u!=='string'||!UNAME.test(u))return{valid:false,available:false,reason:'Use 3-16 letters, numbers or underscore'};
 if(RESERVED.has(u.toLowerCase()))return{valid:true,available:false,reason:'That name is reserved'};
 const r=db.prepare('SELECT id FROM users WHERE username=?').get(u);return{valid:true,available:!r||r.id===uid,reason:r&&r.id!==uid?'Username already taken':''}}
// ---- API ----
const routes={};
routes['POST /api/register']=async(req,res)=>{const ip=req.socket.remoteAddress;if(limited(ip))return fail(res,429,'Too many attempts, wait a minute');
 const b=await body(req),email=String(b.email||'').trim().toLowerCase(),pw=String(b.password||'');
 if(!EMAIL.test(email))return fail(res,400,'Enter a valid email address');if(pw.length<8||pw.length>128)return fail(res,400,'Password must be 8 to 128 characters');
 if(db.prepare('SELECT 1 FROM users WHERE email=?').get(email))return fail(res,409,'An account with this email already exists');
 const salt=crypto.randomBytes(16).toString('hex'),r=db.prepare('INSERT INTO users(email,salt,hash,created) VALUES(?,?,?,?)').run(email,salt,hashPw(pw,salt),now());
 const uid=Number(r.lastInsertRowid);J(res,200,{ok:true,token:newSession(uid),user:pub(db.prepare('SELECT * FROM users WHERE id=?').get(uid))})};
routes['POST /api/login']=async(req,res)=>{const ip=req.socket.remoteAddress;if(limited(ip))return fail(res,429,'Too many attempts, wait a minute');
 const b=await body(req),email=String(b.email||'').trim().toLowerCase(),pw=String(b.password||''),u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
 const h=u?hashPw(pw,u.salt):hashPw(pw,'00'.repeat(16));if(!u||!crypto.timingSafeEqual(Buffer.from(h),Buffer.from(u.hash)))return fail(res,401,'Incorrect email or password');
 J(res,200,{ok:true,token:newSession(u.id),user:pub(u)})};
routes['POST /api/logout']=async(req,res)=>{const t=tokOf(req);if(t)db.prepare('DELETE FROM sessions WHERE token=?').run(t);J(res,200,{ok:true})};
routes['GET /api/username']=async(req,res,url)=>{const u=userByToken(tokOf(req));J(res,200,Object.assign({ok:true},usernameCheck(url.searchParams.get('u')||'',u&&u.id)))};
routes['GET /api/me']=async(req,res)=>{const u=userByToken(tokOf(req));if(!u)return fail(res,401,'Session expired');J(res,200,{ok:true,user:pub(u),progress:getProg(u.id),owned:owned(u.id)})};
routes['POST /api/profile']=async(req,res)=>{const u=userByToken(tokOf(req));if(!u)return fail(res,401,'Session expired');const b=await body(req);
 if(u.setup_done)return fail(res,409,'Character already created');
 if(b.gender!=='male'&&b.gender!=='female')return fail(res,400,'Choose a character');const c=usernameCheck(b.username,u.id);if(!c.valid||!c.available)return fail(res,409,c.reason||'Username unavailable');
 try{db.prepare('UPDATE users SET username=?,gender=?,character_id=?,setup_done=1 WHERE id=?').run(b.username,b.gender,b.gender==='female'?'chioma':'male',u.id)}catch(e){return fail(res,409,'Username already taken')}
 const prog={v:1,name:b.username,money:START_MONEY,hunger:100,energy:100,health:100,x:-45,z:-50,rot:-1.57,zone:'out',rented:{},home:null,secJob:false,inventory:{},fuel:{},fishing:{totalEarned:0,caught:0},job:null,intro:false};
 putProg(u.id,prog);J(res,200,{ok:true,user:pub(db.prepare('SELECT * FROM users WHERE id=?').get(u.id)),progress:prog})};
routes['PUT /api/progress']=async(req,res)=>{const u=userByToken(tokOf(req));if(!u)return fail(res,401,'Session expired');if(!u.setup_done)return fail(res,409,'Finish character setup first');
 const b=await body(req),d=b.data;if(!d||typeof d!=='object'||JSON.stringify(d).length>200e3)return fail(res,400,'Bad progress');
 for(const k of['x','z','money','hunger','energy','health'])if(d[k]!=null&&!Number.isFinite(+d[k]))return fail(res,400,'Bad '+k);
 d.name=u.username;putProg(u.id,d);J(res,200,{ok:true})};
// server-authoritative economy for the new systems
function mutate(u,fn){const p=getProg(u.id);if(!p)return{error:'No save found'};const r=fn(p);if(r&&r.error)return r;putProg(u.id,p);return{ok:true,money:p.money,inventory:p.inventory||{},result:r}}
routes['POST /api/shop/checkout']=async(req,res)=>{const u=userByToken(tokOf(req));if(!u)return fail(res,401,'Session expired');const b=await body(req),items=Array.isArray(b.items)?b.items:[],sm=cfgGet('supermarket');
 const out=mutate(u,p=>{let total=0;const add={};for(const it of items){const pr=sm.products.find(x=>x.id===it.id),q=Math.floor(+it.qty);if(!pr||!(q>0)||q>50)return{error:'Invalid item in basket'};total+=pr.price*q;add[pr.id]=(add[pr.id]||0)+q}
  total=Math.round(total*(1+(sm.taxRate||0)));if(!items.length)return{error:'Your basket is empty'};if(p.money<total)return{error:'Not enough money: you need N'+total.toLocaleString('en-NG')};
  p.money-=total;p.inventory=p.inventory||{};for(const k in add)p.inventory[k]=(p.inventory[k]||0)+add[k];return{total,added:add}});
 out.error?fail(res,402,out.error):J(res,200,Object.assign({ok:true},out))};
routes['POST /api/fishing/payout']=async(req,res)=>{const u=userByToken(tokOf(req));if(!u)return fail(res,401,'Session expired');const b=await body(req),fc=cfgGet('fishing'),catches=Array.isArray(b.catches)?b.catches:[];
 const out=mutate(u,p=>{let total=0,n=0;const cap=fc.bucketCapacity||14;for(const c of catches.slice(0,cap)){const sp=fc.species.find(s=>s.id===c);if(!sp)continue;total+=sp.value;n++}
  total=Math.round(total*(fc.jobPay.sellMultiplier||1))+(n?fc.jobPay.perShift||0:0);p.money+=total;p.fishing=p.fishing||{totalEarned:0,caught:0};p.fishing.totalEarned+=total;p.fishing.caught+=n;return{total,caught:n}});
 out.error?fail(res,400,out.error):J(res,200,Object.assign({ok:true},out))};
routes['POST /api/fuel/buy']=async(req,res)=>{const u=userByToken(tokOf(req));if(!u)return fail(res,401,'Session expired');const b=await body(req),fu=cfgGet('fuel'),litres=Math.max(0,Math.min(200,+b.litres||0));
 const out=mutate(u,p=>{const cost=Math.round(litres*fu.pricePerLitre);if(!(litres>0))return{error:'Nothing to buy'};if(p.money<cost)return{error:'Not enough money for fuel'};p.money-=cost;return{cost,litres}});
 out.error?fail(res,402,out.error):J(res,200,Object.assign({ok:true},out))};
routes['POST /api/inventory/use']=async(req,res)=>{const u=userByToken(tokOf(req));if(!u)return fail(res,401,'Session expired');const b=await body(req),sm=cfgGet('supermarket'),pr=sm.products.find(x=>x.id===b.id);
 const out=mutate(u,p=>{if(!pr)return{error:'Unknown item'};if(!(p.inventory&&p.inventory[pr.id]>0))return{error:'You do not have that'};p.inventory[pr.id]--;if(!p.inventory[pr.id])delete p.inventory[pr.id];p.hunger=Math.min(100,(p.hunger||0)+(pr.hunger||0));return{hunger:p.hunger}});
 out.error?fail(res,400,out.error):J(res,200,Object.assign({ok:true},out))};
routes['GET /api/config']=async(req,res)=>{const c=cfgAll();J(res,200,{ok:true,config:c})};
routes['POST /api/premium/purchase']=async(req,res)=>{const u=userByToken(tokOf(req));if(!u)return fail(res,401,'Session expired');const b=await body(req),pc=cfgGet('premiumCharacters')||[];if(!pc.find(c=>c.id===b.id))return fail(res,404,'Unknown character');
 // No payment provider is connected yet: nothing is purchased, nothing is unlocked, no in-game money is touched.
 J(res,200,{ok:false,status:'coming_soon',message:(cfgGet('payments')||{}).message||'Coming soon'})};
routes['POST /api/premium/select']=async(req,res)=>{const u=userByToken(tokOf(req));if(!u)return fail(res,401,'Session expired');const b=await body(req),pc=cfgGet('premiumCharacters')||[];
 if(b.id==='default'){db.prepare('UPDATE users SET character_id=? WHERE id=?').run(u.gender==='female'?'chioma':'male',u.id);return J(res,200,{ok:true,characterId:u.gender==='female'?'chioma':'male'})}
 const c=pc.find(x=>x.id===b.id);if(!c)return fail(res,404,'Unknown character');if(!owned(u.id).includes(c.id))return fail(res,403,'Locked: purchase required');db.prepare('UPDATE users SET character_id=? WHERE id=?').run(c.id,u.id);J(res,200,{ok:true,characterId:c.id})};
routes['POST /api/character/select']=async(req,res)=>{const u=userByToken(tokOf(req));if(!u)return fail(res,401,'Session expired');const b=await body(req);
 if(b.gender!=='male'&&b.gender!=='female')return fail(res,400,'Bad character');db.prepare('UPDATE users SET gender=?,character_id=? WHERE id=?').run(b.gender,b.gender==='female'?'chioma':'male',u.id);J(res,200,{ok:true,user:pub(db.prepare('SELECT * FROM users WHERE id=?').get(u.id))})};
routes['PUT /api/admin/config']=async(req,res,url)=>{if(!ADMIN_TOKEN||req.headers['x-admin-token']!==ADMIN_TOKEN)return fail(res,403,'Forbidden');const b=await body(req),k=url.searchParams.get('key');if(!k||b.value===undefined)return fail(res,400,'key and value required');
 db.prepare('INSERT INTO config(key,json) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET json=excluded.json').run(k,JSON.stringify(b.value));J(res,200,{ok:true})};
routes['POST /api/admin/grant']=async(req,res)=>{ // for the future verified-payment webhook: requires admin token + a payment reference
 if(!ADMIN_TOKEN||req.headers['x-admin-token']!==ADMIN_TOKEN)return fail(res,403,'Forbidden');const b=await body(req);if(!b.userId||!b.characterId||!b.paymentRef)return fail(res,400,'userId, characterId, paymentRef required');
 db.prepare('INSERT OR REPLACE INTO entitlements(user_id,character_id,payment_ref,verified_at) VALUES(?,?,?,?)').run(b.userId,b.characterId,String(b.paymentRef),now());J(res,200,{ok:true})};
// ---- static ----
const MIME={'.html':'text/html;charset=utf-8','.js':'text/javascript','.json':'application/json','.png':'image/png','.jpg':'image/jpeg','.fbx':'application/octet-stream','.css':'text/css','.svg':'image/svg+xml'};
function serve(req,res,url){let p=decodeURIComponent(url.pathname);if(p==='/')p='/index.html';const f=path.normalize(path.join(ROOT,p));
 if(!f.startsWith(ROOT)||f.startsWith(path.join(ROOT,'server'))||!fs.existsSync(f)||!fs.statSync(f).isFile()){res.writeHead(404);return res.end('Not found')}
 const ext=path.extname(f),h={'Content-Type':MIME[ext]||'application/octet-stream','Cache-Control':ext==='.html'?'no-cache':'public,max-age=86400'},ae=req.headers['accept-encoding']||'';
 if(/\.(html|json|js)$/.test(ext)&&ae.includes('gzip')){h['Content-Encoding']='gzip';res.writeHead(200,h);fs.createReadStream(f).pipe(zlib.createGzip({level:6})).pipe(res)}else{res.writeHead(200,h);fs.createReadStream(f).pipe(res)}}
const server=http.createServer(async(req,res)=>{const url=new URL(req.url,'http://x');try{const h=routes[req.method+' '+url.pathname];if(h)return await h(req,res,url);if(url.pathname.startsWith('/api/'))return fail(res,404,'No such endpoint');serve(req,res,url)}catch(e){if(!res.headersSent)fail(res,500,e.message==='bad json'||e.message==='too large'?e.message:'Server error')}});
// ---- multiplayer (hand-rolled RFC6455 websocket) ----
const players=new Map(),claims=new Map();let nextId=1;
function frame(str){const b=Buffer.from(str),n=b.length;let h;if(n<126)h=Buffer.from([0x81,n]);else if(n<65536){h=Buffer.alloc(4);h[0]=0x81;h[1]=126;h.writeUInt16BE(n,2)}else{h=Buffer.alloc(10);h[0]=0x81;h[1]=127;h.writeBigUInt64BE(BigInt(n),2)}return Buffer.concat([h,b])}
function send(p,o){if(!p.sock.destroyed)p.sock.write(frame(JSON.stringify(o)))}
function bcast(o,except){const f=frame(JSON.stringify(o));for(const p of players.values())if(p!==except&&!p.sock.destroyed)p.sock.write(f)}
function release(p){for(const[k,v]of claims)if(v===p.id){claims.delete(k);bcast({t:'claim',veh:k,by:null})}}
function onMsg(p,m){switch(m.t){
 case 'st':{const s=p.state;for(const k of['x','y','z','r','a','v','vx','vz','vh','vk','u','sp'])if(m[k]!==undefined&&(typeof m[k]==='number'?Number.isFinite(m[k]):typeof m[k]==='string'||m[k]===null))s[k]=typeof m[k]==='string'?m[k].slice(0,24):m[k];break}
 case 'claim':{const k=String(m.veh).slice(0,24),cur=claims.get(k);if(cur&&cur!==p.id&&players.has(cur)){send(p,{t:'claimNo',veh:k,by:cur});break}claims.set(k,p.id);send(p,{t:'claimOk',veh:k});bcast({t:'claim',veh:k,by:p.id},p);break}
 case 'release':{const k=String(m.veh).slice(0,24);if(claims.get(k)===p.id){claims.delete(k);bcast({t:'claim',veh:k,by:null})}break}
 case 'chat':{const tx=String(m.text||'').slice(0,120);if(tx)bcast({t:'chat',id:p.id,name:p.name,text:tx});break}
 case 'ping':send(p,{t:'pong'});}}
server.on('upgrade',(req,sock)=>{const url=new URL(req.url,'http://x');if(url.pathname!=='/ws'){sock.destroy();return}
 const u=userByToken(url.searchParams.get('token'));if(!u||!u.setup_done){sock.write('HTTP/1.1 401 Unauthorized\r\n\r\n');sock.destroy();return}
 const key=req.headers['sec-websocket-key'];if(!key){sock.destroy();return}
 sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+crypto.createHash('sha1').update(key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')+'\r\n\r\n');
 for(const o of players.values())if(o.uid===u.id){o.sock.destroy()} // one session per account
 const p={id:nextId++,uid:u.id,name:u.username,gender:u.gender,cid:u.character_id,sock,state:{x:0,y:0,z:0,r:0,a:'idle',v:0,u:''},buf:Buffer.alloc(0),frag:[]};players.set(p.id,p);
 send(p,{t:'hello',id:p.id,players:[...players.values()].filter(o=>o!==p).map(o=>({id:o.id,name:o.name,gender:o.gender,cid:o.cid,s:o.state})),claims:Object.fromEntries(claims)});
 bcast({t:'join',id:p.id,name:p.name,gender:p.gender,cid:p.cid,s:p.state},p);
 sock.on('data',d=>{p.buf=Buffer.concat([p.buf,d]);for(;;){const b=p.buf;if(b.length<2)return;const op=b[0]&15,fin=!!(b[0]&128),masked=!!(b[1]&128);let len=b[1]&127,o=2;if(len===126){if(b.length<4)return;len=b.readUInt16BE(2);o=4}else if(len===127){if(b.length<10)return;len=Number(b.readBigUInt64BE(2));o=10}
  if(len>65536){sock.destroy();return}if(b.length<o+(masked?4:0)+len)return;let pl=b.subarray(o+(masked?4:0),o+(masked?4:0)+len);if(masked){const mk=b.subarray(o,o+4);pl=Buffer.from(pl);for(let i=0;i<pl.length;i++)pl[i]^=mk[i&3]}
  p.buf=b.subarray(o+(masked?4:0)+len);
  if(op===8){sock.end();return}if(op===9){sock.write(Buffer.concat([Buffer.from([0x8A,pl.length]),pl]));continue}
  if(op===1||op===0){p.frag.push(pl);if(fin){const t=Buffer.concat(p.frag).toString();p.frag=[];try{onMsg(p,JSON.parse(t))}catch(e){}}}}});
 const gone=()=>{if(!players.has(p.id))return;players.delete(p.id);release(p);bcast({t:'leave',id:p.id})};sock.on('close',gone);sock.on('error',gone)});
const tick=setInterval(()=>{if(players.size<2)return;const snap=[...players.values()].map(p=>({id:p.id,s:p.state}));const f=frame(JSON.stringify({t:'snap',p:snap}));for(const p of players.values())if(!p.sock.destroyed)p.sock.write(f)},100);tick.unref();
if(require.main===module)server.listen(PORT,()=>console.log('Lagos Close server on http://localhost:'+PORT));
module.exports={server,db,players,claims};
