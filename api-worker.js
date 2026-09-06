/* الأدب العربي في البكالوريا 2.0
   Shared backend: Cloudflare Workers + D1
   This worker is deliberately API-first; the 1.0 site remains untouched.
*/
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const now = () => new Date().toISOString();
const id = (p='id') => `${p}_${crypto.randomUUID()}`;

const json = (data, status=200, extra={}) => new Response(JSON.stringify(data), {
  status, headers: {'content-type':'application/json; charset=utf-8', 'cache-control':'no-store', ...extra}
});
const bad = (msg, status=400) => json({ok:false,error:msg}, status);
const body = async r => { try { return await r.json(); } catch { return {}; } };

async function sha256(bytes){ return crypto.subtle.digest('SHA-256', bytes); }
function b64u(bytes){ let s=''; for(const b of new Uint8Array(bytes)) s+=String.fromCharCode(b); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function unb64u(s){ s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4)s+='='; const bin=atob(s); return Uint8Array.from(bin,c=>c.charCodeAt(0)); }
async function derivePassword(password, saltB64){
  const salt = saltB64 ? unb64u(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:100000,hash:'SHA-256'}, key, 256);
  return `${b64u(salt)}.${b64u(bits)}`;
}
async function verifyPassword(password, stored){
  const [salt, expected] = String(stored||'').split('.');
  if(!salt || !expected) return false;
  const got = (await derivePassword(password,salt)).split('.')[1];
  return got === expected;
}

async function hmac(secret, text){
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  return b64u(await crypto.subtle.sign('HMAC',key,encoder.encode(text)));
}
async function makeToken(env, payload){
  const raw = b64u(encoder.encode(JSON.stringify({...payload,exp:Date.now()+1000*60*60*24*30}))); 
  return `${raw}.${await hmac(env.SESSION_SECRET,raw)}`;
}
async function readToken(env, token){
  try{
    const [raw,sig] = String(token||'').split('.'); if(!raw||!sig) return null;
    const good = await hmac(env.SESSION_SECRET,raw); if(good!==sig) return null;
    const p = JSON.parse(decoder.decode(unb64u(raw))); if(p.exp<Date.now()) return null; return p;
  }catch{return null;}
}
function bearer(r){ const h=r.headers.get('authorization')||''; return h.startsWith('Bearer ')?h.slice(7):''; }

async function ensureSchema(db){
  const sql = `
CREATE TABLE IF NOT EXISTS students(id TEXT PRIMARY KEY,name TEXT NOT NULL,school TEXT NOT NULL,phone TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'new',class_name TEXT DEFAULT 'آداب',progress INTEGER NOT NULL DEFAULT 0,mission TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_students_phone ON students(phone);
CREATE INDEX IF NOT EXISTS idx_students_status ON students(status);
CREATE TABLE IF NOT EXISTS content_items(id TEXT PRIMARY KEY,axis_no INTEGER NOT NULL CHECK(axis_no BETWEEN 1 AND 5),kind TEXT NOT NULL CHECK(kind IN ('lesson','training','research')),title TEXT NOT NULL,slug TEXT,summary TEXT,body_html TEXT,source_url TEXT,source_mode TEXT NOT NULL DEFAULT 'static' CHECK(source_mode IN ('static','dynamic','external')),status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published','archived')),order_index INTEGER NOT NULL DEFAULT 0,created_by TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_content_axis_kind ON content_items(axis_no,kind,status,order_index);
CREATE TABLE IF NOT EXISTS trainings(id TEXT PRIMARY KEY,content_id TEXT UNIQUE,axis_no INTEGER NOT NULL CHECK(axis_no BETWEEN 1 AND 5),title TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published','archived')),order_index INTEGER NOT NULL DEFAULT 0,created_by TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(content_id) REFERENCES content_items(id) ON DELETE SET NULL);
CREATE TABLE IF NOT EXISTS training_stages(id TEXT PRIMARY KEY,training_id TEXT NOT NULL,stage_no INTEGER NOT NULL CHECK(stage_no BETWEEN 1 AND 4),title TEXT NOT NULL,instructions TEXT,activities_json TEXT NOT NULL DEFAULT '[]',created_at TEXT NOT NULL,updated_at TEXT NOT NULL,UNIQUE(training_id,stage_no),FOREIGN KEY(training_id) REFERENCES trainings(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS missions(id TEXT PRIMARY KEY,student_id TEXT NOT NULL,content_id TEXT,title TEXT NOT NULL,instructions TEXT NOT NULL,due_at TEXT,status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','pending','submitted','reviewed','closed')),submission_text TEXT,submitted_at TEXT,feedback TEXT,reviewed_at TEXT,created_by TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,FOREIGN KEY(content_id) REFERENCES content_items(id) ON DELETE SET NULL);
CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY,sender_type TEXT NOT NULL CHECK(sender_type IN ('student','teacher')),sender_id TEXT NOT NULL,recipient_type TEXT NOT NULL CHECK(recipient_type IN ('student','teacher')),recipient_id TEXT NOT NULL,body TEXT NOT NULL,linked_content_id TEXT,linked_mission_id TEXT,is_read INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,FOREIGN KEY(linked_content_id) REFERENCES content_items(id) ON DELETE SET NULL,FOREIGN KEY(linked_mission_id) REFERENCES missions(id) ON DELETE SET NULL);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_type,recipient_id,is_read,created_at);
CREATE TABLE IF NOT EXISTS tests(id TEXT PRIMARY KEY,axis_no INTEGER CHECK(axis_no BETWEEN 1 AND 5),title TEXT NOT NULL,description TEXT,status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published','archived')),audience TEXT NOT NULL DEFAULT 'assigned' CHECK(audience IN ('public','assigned')),created_by TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS test_questions(id TEXT PRIMARY KEY,test_id TEXT NOT NULL,question_no INTEGER NOT NULL,prompt TEXT NOT NULL,expected_answer TEXT,points REAL NOT NULL DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,UNIQUE(test_id,question_no),FOREIGN KEY(test_id) REFERENCES tests(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS test_assignments(id TEXT PRIMARY KEY,test_id TEXT NOT NULL,student_id TEXT NOT NULL,assigned_at TEXT NOT NULL,FOREIGN KEY(test_id) REFERENCES tests(id) ON DELETE CASCADE,FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,UNIQUE(test_id,student_id));
CREATE TABLE IF NOT EXISTS test_answers(id TEXT PRIMARY KEY,test_id TEXT NOT NULL,question_id TEXT NOT NULL,student_id TEXT NOT NULL,answer_text TEXT NOT NULL,score REAL,feedback TEXT,submitted_at TEXT NOT NULL,reviewed_at TEXT,FOREIGN KEY(test_id) REFERENCES tests(id) ON DELETE CASCADE,FOREIGN KEY(question_id) REFERENCES test_questions(id) ON DELETE CASCADE,FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,UNIQUE(test_id,question_id,student_id));
CREATE TABLE IF NOT EXISTS notes(id TEXT PRIMARY KEY,student_id TEXT NOT NULL,note_type TEXT NOT NULL CHECK(note_type IN ('strength','support','next','general')),linked_content_id TEXT,note_text TEXT NOT NULL,student_reply TEXT,replied_at TEXT,created_by TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,FOREIGN KEY(linked_content_id) REFERENCES content_items(id) ON DELETE SET NULL);
CREATE TABLE IF NOT EXISTS announcements(id TEXT PRIMARY KEY,title TEXT NOT NULL,body TEXT NOT NULL,kind TEXT NOT NULL DEFAULT 'info',linked_content_id TEXT,target_student_id TEXT,published INTEGER NOT NULL DEFAULT 0,created_by TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(linked_content_id) REFERENCES content_items(id) ON DELETE SET NULL,FOREIGN KEY(target_student_id) REFERENCES students(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS media_links(id TEXT PRIMARY KEY,title TEXT NOT NULL,url TEXT NOT NULL,axis_no INTEGER CHECK(axis_no BETWEEN 1 AND 5),description TEXT,status TEXT NOT NULL DEFAULT 'published' CHECK(status IN ('draft','published','archived')),created_by TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS student_progress(id TEXT PRIMARY KEY,student_id TEXT NOT NULL,content_id TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'started' CHECK(state IN ('started','completed')),percent INTEGER NOT NULL DEFAULT 0,last_seen_at TEXT NOT NULL,completed_at TEXT,FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE,FOREIGN KEY(content_id) REFERENCES content_items(id) ON DELETE CASCADE,UNIQUE(student_id,content_id));
CREATE TABLE IF NOT EXISTS activity_logs(id TEXT PRIMARY KEY,actor_type TEXT NOT NULL CHECK(actor_type IN ('student','teacher','system')),actor_id TEXT,action TEXT NOT NULL,level TEXT NOT NULL DEFAULT 'info' CHECK(level IN ('info','warning','error')),details_json TEXT,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS platform_settings(setting_key TEXT PRIMARY KEY,setting_value TEXT NOT NULL,updated_by TEXT,updated_at TEXT NOT NULL);
`;
  // D1 batch executes statements separated by semicolons.
  const stmts = sql.split(';').map(s=>s.trim()).filter(Boolean).map(s=>db.prepare(s));
  await db.batch(stmts);
}

async function log(db, actor_type, actor_id, action, level='info', details={}){
  try{await db.prepare(`INSERT INTO activity_logs(id,actor_type,actor_id,action,level,details_json,created_at) VALUES(?,?,?,?,?,?,?)`).bind(id('log'),actor_type,actor_id||null,action,level,JSON.stringify(details),now()).run();}catch{}
}
function studentView(s){ if(!s)return null; const {password_hash,...safe}=s; return safe; }

async function requireStudent(env,r){
  const p=await readToken(env,bearer(r));
  if(!p||p.type!=='student'||!p.sub)return null;
  return await env.DB.prepare('SELECT * FROM students WHERE id=?').bind(p.sub).first();
}
async function requireTeacher(env,r){
  const p=await readToken(env,bearer(r));
  return p&&p.type==='teacher'?p:null;
}

async function api(env,r,url){
  await ensureSchema(env.DB);
  const path=url.pathname;
  const method=r.method.toUpperCase();

  if(path==='/api/health'&&method==='GET') return json({ok:true,service:'adab-arabi-2.0',time:now(),database:true});

  if(path==='/api/signup'&&method==='POST'){
    const b=await body(r); const name=String(b.name||'').trim(), school=String(b.school||'').trim(), phone=String(b.phone||'').trim(), password=String(b.password||'');
    if(name.length<2||school.length<2||phone.length<6||password.length<6)return bad('بيانات التسجيل غير مكتملة');
    const exists=await env.DB.prepare('SELECT id FROM students WHERE phone=?').bind(phone).first();
    if(exists)return bad('رقم الهاتف مسجل مسبقًا',409);
    const ts=now(), sid=id('stu'), hash=await derivePassword(password);
    await env.DB.prepare(`INSERT INTO students(id,name,school,phone,password_hash,status,class_name,progress,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(sid,name,school,phone,hash,'new',String(b.class_name||'آداب'),0,ts,ts).run();
    const token=await makeToken(env,{type:'student',sub:sid}); await log(env.DB,'student',sid,'signup');
    return json({ok:true,token,student:studentView(await env.DB.prepare('SELECT * FROM students WHERE id=?').bind(sid).first())},201);
  }

  if(path==='/api/login'&&method==='POST'){
    const b=await body(r); const phone=String(b.phone||'').trim(), password=String(b.password||'');
    const s=await env.DB.prepare('SELECT * FROM students WHERE phone=?').bind(phone).first();
    if(!s||!(await verifyPassword(password,s.password_hash))){await log(env.DB,'system',null,'student_login_failed','warning',{phone});return bad('بيانات الدخول غير صحيحة',401);}
    if(s.status==='suspended')return bad('هذا الحساب موقوف',403);
    const token=await makeToken(env,{type:'student',sub:s.id}); await log(env.DB,'student',s.id,'login');
    return json({ok:true,token,student:studentView(s)});
  }

  if(path==='/api/me'&&method==='GET'){
    const s=await requireStudent(env,r); if(!s)return bad('جلسة غير صالحة',401);
    return json({ok:true,student:studentView(s)});
  }

  if(path==='/api/teacher/login'&&method==='POST'){
    const b=await body(r); if(String(b.username||'')!==String(env.TEACHER_USER||'')||String(b.password||'')!==String(env.TEACHER_PASS||'')){await log(env.DB,'system',null,'teacher_login_failed','warning');return bad('بيانات الأستاذ غير صحيحة',401);}
    const token=await makeToken(env,{type:'teacher',sub:'teacher'}); await log(env.DB,'teacher','teacher','login'); return json({ok:true,token});
  }

  if(path==='/api/teacher/students'&&method==='GET'){
    if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);
    const rows=await env.DB.prepare('SELECT id,name,school,phone,status,class_name,progress,mission,created_at,updated_at FROM students ORDER BY created_at DESC').all();
    return json({ok:true,students:rows.results||[]});
  }

  const sm=path.match(/^\/api\/teacher\/students\/([^/]+)$/);
  if(sm&&method==='PATCH'){
    if(!(await requireTeacher(env,r)))return bad('غير مصرح',401); const sid=sm[1], b=await body(r);
    const allowed=['status','class_name','progress','mission']; const fields=[]; const vals=[];
    for(const k of allowed)if(Object.prototype.hasOwnProperty.call(b,k)){fields.push(`${k}=?`);vals.push(b[k]);}
    if(!fields.length)return bad('لا توجد تغييرات'); vals.push(now(),sid);
    await env.DB.prepare(`UPDATE students SET ${fields.join(',')},updated_at=? WHERE id=?`).bind(...vals).run(); await log(env.DB,'teacher','teacher','update_student','info',{sid});
    return json({ok:true,student:studentView(await env.DB.prepare('SELECT * FROM students WHERE id=?').bind(sid).first())});
  }

  // Published content for students / public browsing.
  if(path==='/api/content'&&method==='GET'){
    const u=new URL(r.url), axis=u.searchParams.get('axis'), kind=u.searchParams.get('kind');
    let sql='SELECT id,axis_no,kind,title,slug,summary,body_html,source_url,source_mode,order_index,created_at,updated_at FROM content_items WHERE status=\'published\'', vals=[];
    if(axis){sql+=' AND axis_no=?';vals.push(Number(axis));} if(kind){sql+=' AND kind=?';vals.push(kind);} sql+=' ORDER BY axis_no,kind,order_index,title';
    const rows=await env.DB.prepare(sql).bind(...vals).all(); return json({ok:true,items:rows.results||[]});
  }

  if(path==='/api/student/messages'&&method==='GET'){
    const s=await requireStudent(env,r); if(!s)return bad('غير مصرح',401);
    const rows=await env.DB.prepare('SELECT * FROM messages WHERE recipient_type=\'student\' AND recipient_id=? OR sender_type=\'student\' AND sender_id=? ORDER BY created_at DESC').bind(s.id,s.id).all(); return json({ok:true,messages:rows.results||[]});
  }
  if(path==='/api/student/messages'&&method==='POST'){
    const s=await requireStudent(env,r); if(!s)return bad('غير مصرح',401); const b=await body(r), text=String(b.body||'').trim(); if(!text)return bad('الرسالة فارغة');
    const mid=id('msg'); await env.DB.prepare(`INSERT INTO messages(id,sender_type,sender_id,recipient_type,recipient_id,body,linked_content_id,linked_mission_id,is_read,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(mid,'student',s.id,'teacher','teacher',text,b.linked_content_id||null,b.linked_mission_id||null,0,now()).run(); await log(env.DB,'student',s.id,'send_message'); return json({ok:true,id:mid},201);
  }

  if(path==='/api/student/missions'&&method==='GET'){
    const s=await requireStudent(env,r); if(!s)return bad('غير مصرح',401); const rows=await env.DB.prepare('SELECT * FROM missions WHERE student_id=? ORDER BY created_at DESC').bind(s.id).all(); return json({ok:true,missions:rows.results||[]});
  }
  const subm=path.match(/^\/api\/student\/missions\/([^/]+)\/submit$/);
  if(subm&&method==='POST'){
    const s=await requireStudent(env,r); if(!s)return bad('غير مصرح',401); const b=await body(r), text=String(b.submission_text||'').trim(); if(!text)return bad('الإنتاج فارغ');
    const ts=now(); const res=await env.DB.prepare(`UPDATE missions SET submission_text=?,submitted_at=?,status='submitted',updated_at=? WHERE id=? AND student_id=?`).bind(text,ts,ts,subm[1],s.id).run(); if(!res.meta.changes)return bad('المهمة غير موجودة',404); await log(env.DB,'student',s.id,'submit_mission',{mission_id:subm[1]}); return json({ok:true});
  }

  if(path==='/api/student/tests'&&method==='GET'){
    const s=await requireStudent(env,r); if(!s)return bad('غير مصرح',401);
    const rows=await env.DB.prepare(`SELECT DISTINCT t.* FROM tests t LEFT JOIN test_assignments a ON a.test_id=t.id WHERE t.status='published' AND (t.audience='public' OR a.student_id=?) ORDER BY t.created_at DESC`).bind(s.id).all();
    const tests=[];
    for(const t of (rows.results||[])){
      const q=await env.DB.prepare('SELECT id,question_no,prompt,points FROM test_questions WHERE test_id=? ORDER BY question_no').bind(t.id).all();
      const a=await env.DB.prepare('SELECT question_id,answer_text,score,feedback,submitted_at,reviewed_at FROM test_answers WHERE test_id=? AND student_id=?').bind(t.id,s.id).all();
      tests.push({...t,questions:q.results||[],answers:a.results||[]});
    }
    return json({ok:true,tests});
  }
  if(path==='/api/student/answers'&&method==='POST'){
    const s=await requireStudent(env,r); if(!s)return bad('غير مصرح',401); const b=await body(r); if(!b.test_id||!b.question_id)return bad('بيانات الإجابة ناقصة');
    const ts=now(); await env.DB.prepare(`INSERT INTO test_answers(id,test_id,question_id,student_id,answer_text,submitted_at) VALUES(?,?,?,?,?,?) ON CONFLICT(test_id,question_id,student_id) DO UPDATE SET answer_text=excluded.answer_text,submitted_at=excluded.submitted_at`).bind(id('ans'),b.test_id,b.question_id,s.id,String(b.answer_text||''),ts).run(); await log(env.DB,'student',s.id,'submit_test_answer',{test_id:b.test_id,question_id:b.question_id}); return json({ok:true});
  }

  if(path==='/api/student/notes'&&method==='GET'){
    const s=await requireStudent(env,r); if(!s)return bad('غير مصرح',401); const rows=await env.DB.prepare('SELECT * FROM notes WHERE student_id=? ORDER BY created_at DESC').bind(s.id).all(); return json({ok:true,notes:rows.results||[]});
  }
  const nr=path.match(/^\/api\/student\/notes\/([^/]+)\/reply$/);
  if(nr&&method==='POST'){
    const s=await requireStudent(env,r); if(!s)return bad('غير مصرح',401); const b=await body(r), reply=String(b.student_reply||'').trim(); if(!reply)return bad('الرد فارغ');
    const ts=now(); const res=await env.DB.prepare('UPDATE notes SET student_reply=?,replied_at=?,updated_at=? WHERE id=? AND student_id=?').bind(reply,ts,ts,nr[1],s.id).run(); if(!res.meta.changes)return bad('الملاحظة غير موجودة',404); await log(env.DB,'student',s.id,'reply_to_note',{note_id:nr[1]}); return json({ok:true});
  }

  if(path==='/api/student/announcements'&&method==='GET'){
    const s=await requireStudent(env,r); if(!s)return bad('غير مصرح',401); const rows=await env.DB.prepare(`SELECT * FROM announcements WHERE published=1 AND (target_student_id IS NULL OR target_student_id=?) ORDER BY created_at DESC`).bind(s.id).all(); return json({ok:true,announcements:rows.results||[]});
  }

  if(path==='/api/student/progress'&&method==='GET'){
    const s=await requireStudent(env,r); if(!s)return bad('غير مصرح',401); const rows=await env.DB.prepare('SELECT * FROM student_progress WHERE student_id=? ORDER BY last_seen_at DESC').bind(s.id).all(); return json({ok:true,progress:rows.results||[]});
  }
  if(path==='/api/student/progress'&&method==='POST'){
    const s=await requireStudent(env,r); if(!s)return bad('غير مصرح',401); const b=await body(r); if(!b.content_id)return bad('المحتوى غير محدد'); const pct=Math.max(0,Math.min(100,Number(b.percent||0))); const state=pct>=100?'completed':'started'; const ts=now();
    await env.DB.prepare(`INSERT INTO student_progress(id,student_id,content_id,state,percent,last_seen_at,completed_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(student_id,content_id) DO UPDATE SET state=excluded.state,percent=excluded.percent,last_seen_at=excluded.last_seen_at,completed_at=excluded.completed_at`).bind(id('prog'),s.id,b.content_id,state,pct,ts,state==='completed'?ts:null).run(); return json({ok:true});
  }

  if(path==='/api/student/progress/overall'&&method==='POST'){
    const s=await requireStudent(env,r); if(!s)return bad('غير مصرح',401); const b=await body(r); const inc=Number(b.increment||0); const next=Math.max(0,Math.min(100,Number(s.progress||0)+inc));
    await env.DB.prepare('UPDATE students SET progress=?,updated_at=? WHERE id=?').bind(next,now(),s.id).run(); await log(env.DB,'student',s.id,'update_overall_progress',{progress:next}); return json({ok:true,progress:next});
  }

  // Teacher content management.
  if(path==='/api/teacher/content/bootstrap'&&method==='POST'){
    if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);
    const b=await body(r), items=Array.isArray(b.items)?b.items:[]; if(!items.length)return bad('لا توجد موارد للتهيئة');
    let inserted=0,updated=0; const ts=now();
    for(const x of items){
      if(!x.id||!x.title||!x.axis||!x.kind)continue;
      const kind=x.kind==='lessons'?'lesson':(x.kind==='training'?'training':'research');
      const sourceUrl=x.file?String(x.category==='lessons'?'lessons__':x.category==='training'?'training__':'research__')+String(x.file):null;
      const exists=await env.DB.prepare('SELECT id FROM content_items WHERE id=?').bind(String(x.id)).first();
      if(exists){
        await env.DB.prepare(`UPDATE content_items SET axis_no=?,kind=?,title=?,summary=?,source_url=?,source_mode='static',status=CASE WHEN status='draft' THEN 'published' ELSE status END,order_index=?,updated_at=? WHERE id=?`).bind(Number(x.axis),kind,String(x.title),x.summary||null,sourceUrl,Number(x.number||0),ts,String(x.id)).run(); updated++;
      }else{
        await env.DB.prepare(`INSERT INTO content_items(id,axis_no,kind,title,slug,summary,body_html,source_url,source_mode,status,order_index,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(String(x.id),Number(x.axis),kind,String(x.title),null,x.summary||null,null,sourceUrl,'static','published',Number(x.number||0),'system',ts,ts).run(); inserted++;
      }
    }
    await log(env.DB,'teacher','teacher','bootstrap_content','info',{inserted,updated}); return json({ok:true,inserted,updated});
  }
  if(path==='/api/content'&&method==='GET'){
    const u=new URL(r.url), axis=u.searchParams.get('axis'), kind=u.searchParams.get('kind'); let sql='SELECT id,axis_no,kind,title,slug,summary,body_html,source_url,source_mode,status,order_index,created_at,updated_at FROM content_items WHERE status=\'published\'', vals=[];
    if(axis){sql+=' AND axis_no=?';vals.push(Number(axis));} if(kind){sql+=' AND kind=?';vals.push(kind==='lessons'?'lesson':kind);} sql+=' ORDER BY axis_no,kind,order_index,title'; const rows=await env.DB.prepare(sql).bind(...vals).all(); return json({ok:true,items:rows.results||[]});
  }
  const contentGet=path.match(/^\/api\/content\/([^/]+)$/);
  if(contentGet&&method==='GET'){ const row=await env.DB.prepare('SELECT * FROM content_items WHERE id=? AND status=\'published\'').bind(contentGet[1]).first(); if(!row)return bad('المحتوى غير موجود',404); return json({ok:true,item:row}); }
  if(path==='/api/teacher/content'&&method==='GET'){
    if(!(await requireTeacher(env,r)))return bad('غير مصرح',401); const rows=await env.DB.prepare('SELECT * FROM content_items ORDER BY axis_no,kind,order_index,title').all(); return json({ok:true,items:rows.results||[]});
  }
  if(path==='/api/teacher/content'&&method==='POST'){
    const t=await requireTeacher(env,r); if(!t)return bad('غير مصرح',401); const b=await body(r); if(!b.title||!b.axis_no||!b.kind)return bad('بيانات المحتوى ناقصة'); const ts=now(), cid=id('content');
    await env.DB.prepare(`INSERT INTO content_items(id,axis_no,kind,title,slug,summary,body_html,source_url,source_mode,status,order_index,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(cid,Number(b.axis_no),b.kind,b.title,b.slug||null,b.summary||null,b.body_html||null,b.source_url||null,b.source_mode||'dynamic',b.status||'draft',Number(b.order_index||0),'teacher',ts,ts).run(); await log(env.DB,'teacher','teacher','create_content',{content_id:cid}); return json({ok:true,id:cid},201);
  }
  const cr=path.match(/^\/api\/teacher\/content\/([^/]+)$/);
  if(cr&&(method==='PATCH'||method==='DELETE')){
    if(!(await requireTeacher(env,r)))return bad('غير مصرح',401); const cid=cr[1];
    if(method==='DELETE'){await env.DB.prepare('UPDATE content_items SET status=\'archived\',updated_at=? WHERE id=?').bind(now(),cid).run(); await log(env.DB,'teacher','teacher','archive_content',{content_id:cid}); return json({ok:true});}
    const b=await body(r), allowed=['axis_no','kind','title','slug','summary','body_html','source_url','source_mode','status','order_index']; const sets=[],vals=[]; for(const k of allowed)if(k in b){sets.push(`${k}=?`);vals.push(b[k]);} if(!sets.length)return bad('لا توجد تغييرات'); vals.push(now(),cid); await env.DB.prepare(`UPDATE content_items SET ${sets.join(',')},updated_at=? WHERE id=?`).bind(...vals).run(); await log(env.DB,'teacher','teacher','update_content',{content_id:cid}); return json({ok:true});
  }

  // Teacher missions/messages/notes/announcements/tests/media.
  if(path==='/api/teacher/missions'&&method==='GET'){if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);const rows=await env.DB.prepare('SELECT m.*,s.name student_name FROM missions m JOIN students s ON s.id=m.student_id ORDER BY m.created_at DESC').all();return json({ok:true,missions:rows.results||[]});}
  if(path==='/api/teacher/missions'&&method==='POST'){if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);const b=await body(r);if(!b.student_id||!b.title||!b.instructions)return bad('بيانات المهمة ناقصة');const ts=now(),mid=id('mission');await env.DB.prepare(`INSERT INTO missions(id,student_id,content_id,title,instructions,due_at,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(mid,b.student_id,b.content_id||null,b.title,b.instructions,b.due_at||null,'new','teacher',ts,ts).run();return json({ok:true,id:mid},201);}
  const mr=path.match(/^\/api\/teacher\/missions\/([^/]+)\/review$/); if(mr&&method==='POST'){if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);const b=await body(r),ts=now();await env.DB.prepare(`UPDATE missions SET feedback=?,status='reviewed',reviewed_at=?,updated_at=? WHERE id=?`).bind(String(b.feedback||''),ts,ts,mr[1]).run();return json({ok:true});}

  if(path==='/api/teacher/messages'&&method==='GET'){if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);const rows=await env.DB.prepare('SELECT * FROM messages ORDER BY created_at DESC').all();return json({ok:true,messages:rows.results||[]});}
  if(path==='/api/teacher/messages'&&method==='POST'){if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);const b=await body(r),text=String(b.body||'').trim();if(!b.student_id||!text)return bad('بيانات الرسالة ناقصة');const mid=id('msg'),ts=now();await env.DB.prepare(`INSERT INTO messages(id,sender_type,sender_id,recipient_type,recipient_id,body,linked_content_id,linked_mission_id,is_read,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(mid,'teacher','teacher','student',b.student_id,text,b.linked_content_id||null,b.linked_mission_id||null,0,ts).run();await env.DB.prepare(`UPDATE messages SET is_read=1 WHERE sender_type='student' AND sender_id=? AND recipient_type='teacher'`).bind(b.student_id).run();return json({ok:true,id:mid},201);}

  if(path==='/api/teacher/notes'&&method==='GET'){if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);const rows=await env.DB.prepare('SELECT n.*,s.name student_name FROM notes n JOIN students s ON s.id=n.student_id ORDER BY n.created_at DESC').all();return json({ok:true,notes:rows.results||[]});}
  if(path==='/api/teacher/notes'&&method==='POST'){if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);const b=await body(r);if(!b.student_id||!b.note_text)return bad('بيانات الملاحظة ناقصة');const ts=now(),nid=id('note');await env.DB.prepare(`INSERT INTO notes(id,student_id,note_type,linked_content_id,note_text,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`).bind(nid,b.student_id,b.note_type||'general',b.linked_content_id||null,b.note_text,'teacher',ts,ts).run();return json({ok:true,id:nid},201);}

  if(path==='/api/teacher/announcements'&&method==='GET'){if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);const rows=await env.DB.prepare('SELECT * FROM announcements ORDER BY created_at DESC').all();return json({ok:true,announcements:rows.results||[]});}
  if(path==='/api/teacher/announcements'&&method==='POST'){if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);const b=await body(r);if(!b.title||!b.body)return bad('بيانات الإعلان ناقصة');const ts=now(),aid=id('ann');await env.DB.prepare(`INSERT INTO announcements(id,title,body,kind,linked_content_id,target_student_id,published,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(aid,b.title,b.body,b.kind||'info',b.linked_content_id||null,b.target_student_id||null,b.published?1:0,'teacher',ts,ts).run();return json({ok:true,id:aid},201);}

  if(path==='/api/teacher/media'&&method==='GET'){if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);const rows=await env.DB.prepare('SELECT * FROM media_links ORDER BY created_at DESC').all();return json({ok:true,media:rows.results||[]});}
  if(path==='/api/teacher/media'&&method==='POST'){if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);const b=await body(r);if(!b.title||!b.url)return bad('العنوان والرابط مطلوبان');const ts=now(),mid=id('media');await env.DB.prepare(`INSERT INTO media_links(id,title,url,axis_no,description,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`).bind(mid,b.title,b.url,b.axis_no||null,b.description||null,b.status||'published','teacher',ts,ts).run();return json({ok:true,id:mid},201);}

  if(path==='/api/teacher/tests'&&method==='GET'){
    if(!(await requireTeacher(env,r)))return bad('غير مصرح',401); const rows=await env.DB.prepare('SELECT * FROM tests ORDER BY created_at DESC').all(); const tests=[];
    for(const t of (rows.results||[])){const q=await env.DB.prepare('SELECT id,question_no,prompt,points FROM test_questions WHERE test_id=? ORDER BY question_no').bind(t.id).all(); const a=await env.DB.prepare('SELECT * FROM test_answers WHERE test_id=? ORDER BY submitted_at DESC').bind(t.id).all(); const as=await env.DB.prepare('SELECT * FROM test_assignments WHERE test_id=?').bind(t.id).all(); tests.push({...t,questions:q.results||[],answers:a.results||[],assignments:as.results||[]});}
    return json({ok:true,tests});
  }
  if(path==='/api/teacher/tests'&&method==='POST'){if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);const b=await body(r);if(!b.title)return bad('عنوان الاختبار مطلوب');const ts=now(),tid=id('test'),status=b.published?'published':(b.status||'draft'),audience=b.student_id?'assigned':(b.audience||'public');await env.DB.prepare(`INSERT INTO tests(id,axis_no,title,description,status,audience,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`).bind(tid,b.axis_no||null,b.title,b.description||null,status,audience,'teacher',ts,ts).run();if(Array.isArray(b.questions)){for(let i=0;i<b.questions.length;i++){const q=b.questions[i];await env.DB.prepare(`INSERT INTO test_questions(id,test_id,question_no,prompt,expected_answer,points,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`).bind(id('q'),tid,i+1,q.prompt,q.expected_answer||null,Number(q.points||1),ts,ts).run();}}if(b.student_id){await env.DB.prepare(`INSERT OR IGNORE INTO test_assignments(id,test_id,student_id,assigned_at) VALUES(?,?,?,?)`).bind(id('assign'),tid,String(b.student_id),ts).run();}return json({ok:true,id:tid},201);}

  if(path==='/api/teacher/settings'&&method==='GET'){if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);const rows=await env.DB.prepare('SELECT * FROM platform_settings ORDER BY setting_key').all();return json({ok:true,settings:rows.results||[]});}
  if(path==='/api/teacher/settings'&&method==='POST'){if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);const b=await body(r);if(!b.setting_key)return bad('مفتاح الإعداد مطلوب');const ts=now();await env.DB.prepare(`INSERT INTO platform_settings(setting_key,setting_value,updated_by,updated_at) VALUES(?,?,?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_by=excluded.updated_by,updated_at=excluded.updated_at`).bind(b.setting_key,String(b.setting_value??''),'teacher',ts).run();return json({ok:true});}

  if(path==='/api/teacher/activity'&&method==='GET'){if(!(await requireTeacher(env,r)))return bad('غير مصرح',401);const rows=await env.DB.prepare('SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 500').all();return json({ok:true,logs:rows.results||[]});}

  return bad('المسار غير موجود',404);
}

const PRIVATE_STATIC_PATHS = new Set([
  "/api-worker.js",
  "/schema.sql",
  "/wrangler.toml",
  "/DEPLOY_TEST.txt",
  "/.gitignore",
]);

export default {
  async fetch(request, env){
    const url=new URL(request.url);
    if(url.pathname.startsWith('/api/')){
      try{return await api(env,request,url);}catch(e){console.error(e);return json({ok:false,error:'حدث خطأ داخلي',detail:env.ENVIRONMENT==='development'?String(e):undefined},500);}
    }
    const cm=url.pathname.match(/^\/content\/([^/]+)$/);
    if(cm){
      try{
        await ensureSchema(env.DB); const row=await env.DB.prepare('SELECT * FROM content_items WHERE id=? AND status=\'published\'').bind(cm[1]).first();
        if(!row)return new Response('المحتوى غير موجود',{status:404,headers:{'content-type':'text/plain; charset=utf-8'}});
        if(row.source_url)return Response.redirect(new URL('/'+row.source_url,url).toString(),302);
        const html=`<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#0f8f92"><title>${String(row.title).replace(/</g,'&lt;')}</title></head><body style="font-family:Amiri,serif;background:#eefafa;color:#124b52;padding:30px"><main style="max-width:900px;margin:auto;background:white;border-radius:24px;padding:30px;box-shadow:0 10px 30px rgba(0,80,90,.12)"><h1>${String(row.title).replace(/</g,'&lt;')}</h1>${row.summary?`<p>${String(row.summary)}</p>`:''}${row.body_html||'<p>سيظهر المحتوى هنا بعد نشره.</p>'}</main></body></html>`;
        return new Response(html,{headers:{'content-type':'text/html; charset=utf-8'}});
      }catch(e){return new Response('خطأ في المحتوى',{status:500});}
    }
    if (PRIVATE_STATIC_PATHS.has(new URL(request.url).pathname)) {
      return new Response("Not found", {status: 404});
    }
    return env.ASSETS.fetch(request);
  }
};
