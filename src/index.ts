interface Env { DB: D1Database }
const encoder = new TextEncoder();
const hex = (a: Uint8Array) => [...a].map(v => v.toString(16).padStart(2, "0")).join("");
const bytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
async function digest(s: string) { return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(s)))); }
async function passwordHash(password: string, salt: string) {
 const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
 return hex(new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",salt:Uint8Array.from(salt.match(/../g)!.map(x=>parseInt(x,16))),iterations:310000,hash:"SHA-256"},key,256)));
}
const json=(data:unknown,status=200,headers:HeadersInit={})=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...headers}});
const cookie=(token:string,maxAge:number)=>`hyram_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
async function currentUser(req:Request,env:Env) {
 const token=req.headers.get("cookie")?.match(/(?:^|;\s*)hyram_session=([a-f0-9]{64})(?:;|$)/)?.[1];
 if(!token)return null;
 return env.DB.prepare("SELECT u.id,u.email,u.name FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?").bind(await digest(token),Date.now()).first<{id:string;email:string;name:string}>();
}
export default {async fetch(req:Request,env:Env):Promise<Response>{
 const url=new URL(req.url),path=url.pathname;
 if(path==="/api/auth/me"&&req.method==="GET"){const user=await currentUser(req,env);return user?json({user}):json({error:"인증이 필요합니다."},401);}
 if(path==="/api/auth/logout"&&req.method==="POST"){
  const token=req.headers.get("cookie")?.match(/(?:^|;\s*)hyram_session=([a-f0-9]{64})(?:;|$)/)?.[1];
  if(token)await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();
  return json({ok:true},200,{"set-cookie":cookie("",0)});
 }
 if((path==="/api/auth/register"||path==="/api/auth/login")&&req.method==="POST"){
  if(req.headers.get("content-type")?.split(";")[0].trim()!=="application/json")return json({error:"JSON 요청만 허용됩니다."},415);
  if(Number(req.headers.get("content-length")||0)>4096)return json({error:"요청이 너무 큽니다."},413);
  let body:Record<string,unknown>;
  try{body=await req.json() as Record<string,unknown>;}catch{return json({error:"JSON 형식 오류"},400);}
  const email=typeof body.email==="string"?body.email.trim().toLowerCase():"";
  const password=typeof body.password==="string"?body.password:"";
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254||password.length<12||password.length>128)return json({error:"이메일 또는 비밀번호 형식이 올바르지 않습니다. 비밀번호는 12~128자여야 합니다."},400);
  if(path.endsWith("register")){
   const name=typeof body.name==="string"?body.name.trim():"";
   if(name.length<1||name.length>80)return json({error:"이름은 1~80자여야 합니다."},400);
   const salt=hex(bytes(16)),hash=await passwordHash(password,salt),id=crypto.randomUUID();
   try{await env.DB.prepare("INSERT INTO users (id,email,name,password_salt,password_hash) VALUES (?,?,?,?,?)").bind(id,email,name,salt,hash).run();}
   catch{return json({error:"가입할 수 없습니다. 이메일 중복 여부를 확인하세요."},409);}
   return json({ok:true},201);
  }
  const row=await env.DB.prepare("SELECT id,password_salt,password_hash FROM users WHERE email=?").bind(email).first<{id:string;password_salt:string;password_hash:string}>();
  const salt=row?.password_salt||hex(new Uint8Array(16)),expected=row?.password_hash||"0".repeat(64),actual=await passwordHash(password,salt);
  if(!row||actual!==expected)return json({error:"이메일 또는 비밀번호가 올바르지 않습니다."},401);
  const token=hex(bytes(32)),ttl=7*86400;
  await env.DB.prepare("INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)").bind(await digest(token),row.id,Date.now()+ttl*1000).run();
  return json({ok:true},200,{"set-cookie":cookie(token,ttl)});
 }
 return json({error:"Not found"},404);
}} satisfies ExportedHandler<Env>;
