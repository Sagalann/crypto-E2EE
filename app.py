import os, json, time, base64, secrets, string, hashlib, math, threading, uuid
import requests
from flask import Flask, request, jsonify, render_template
from crypto import *

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

GROQ_API_KEY  = os.environ.get("GROQ_API_KEY", "сюда_вставь_ключ")

# ── Document text extraction ────────────────────────────────
def extract_text_from_file(meta):
    """Extract readable text from uploaded file for AI analysis."""
    try:
        data = base64.b64decode(meta['data'])
        mime = meta['mime']
        name = meta['name'].lower()

        if mime == 'text/plain' or name.endswith('.txt') or name.endswith('.md'):
            return data.decode('utf-8', errors='ignore')[:4000]

        if mime == 'application/json' or name.endswith('.json'):
            return data.decode('utf-8', errors='ignore')[:4000]

        if name.endswith('.csv'):
            return data.decode('utf-8', errors='ignore')[:3000]

        if mime == 'application/pdf' or name.endswith('.pdf'):
            try:
                import fitz  # PyMuPDF
                doc = fitz.open(stream=data, filetype='pdf')
                text = ''.join(p.get_text() for p in doc)
                return text[:4000]
            except ImportError:
                return None

        if name.endswith('.docx'):
            try:
                import docx, io
                doc = docx.Document(io.BytesIO(data))
                return '\n'.join(p.text for p in doc.paragraphs)[:4000]
            except ImportError:
                return None

        return None
    except Exception as e:
        print(f"extract_text error: {e}")
        return None
GROQ_URL      = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL    = "llama-3.3-70b-versatile"
BOT_ID        = "Crypto_Assistor"
SYSTEM_PROMPT = (
    "Ты Crypto Assistant — помощник по криптографии и кибербезопасности. "
    "Отвечай кратко. Используй HTML: <b>жирный</b>, <code>код</code>, <br>. "
    "Не используй markdown."
)

users       = {}   # { uid: pub_key_b64 }
messages    = {}   # { uid: [{from, ciphertext, msg_id, ts}] }
profiles    = {}
user_keys   = {}
passwords   = {}
chat_msgs   = {}   # { "u1:u2": [{id, from, text, ts, read, reply_to, file_id}] }
last_seen   = {}   # { uid: timestamp }
groups      = {}   # { gid: {name, avatar, members, created_by} }
group_msgs  = {}   # { gid: [{id, from, text, ts, reply_to, file_id}] }
files_store = {}   # { fid: {name, mime, data, uploaded_by, ts} }
chat_requests  = {} # { to_uid: [{id, from, ts, status}] }
channels       = {} # { cid: {name, avatar, about, owner, subscribers, ts} }
channel_posts  = {} # { cid: [{id, from, text, ts, file_id}] }
push_tokens    = {} # { uid: [subscription_info] }  — Web Push

bot_priv, bot_pub = generate_identity_keypair()
users[BOT_ID]    = b64_encode_key(bot_pub)
messages[BOT_ID] = []
profiles[BOT_ID] = {"display_name":"Crypto Assistant","avatar":"🤖","status":"E2EE · всегда онлайн","theme":"dark"}
last_seen[BOT_ID] = time.time()

def chat_key(a, b): return ':'.join(sorted([a, b]))
def is_online(uid): return uid in last_seen and (time.time()-last_seen[uid]) < 15
def touch(uid): last_seen[uid] = time.time()

@app.route('/')
def index(): return render_template('chat.html')

# ── Auth ───────────────────────────────────────────────────
@app.post('/login')
def login():
    data = request.json
    uid  = data.get('user_id','').strip()
    pw   = data.get('password','').strip()
    if not uid or not pw:
        return jsonify({"status":"error","message":"Введите ник и пароль"}), 400
    pwh = hashlib.sha256(pw.encode()).hexdigest()
    if uid not in passwords:
        passwords[uid]=pwh
        priv,pub=generate_identity_keypair()
        user_keys[uid]=b64_encode_key(priv); users[uid]=b64_encode_key(pub)
        messages[uid]=[]; profiles[uid]={"display_name":uid,"avatar":"🙂","status":"","theme":"dark","is_private":False}
        touch(uid)
        return jsonify({"status":"ok","user_id":uid,"new":True})
    if passwords[uid]!=pwh:
        return jsonify({"status":"error","message":"Неверный пароль"}), 401
    messages.setdefault(uid,[]); profiles.setdefault(uid,{"display_name":uid,"avatar":"🙂","status":"","theme":"dark"})
    touch(uid)
    return jsonify({"status":"ok","user_id":uid,"new":False})

@app.post('/heartbeat')
def heartbeat():
    uid=request.json.get('user_id','')
    if uid in users: touch(uid)
    return jsonify({"status":"ok"})

# ── Users / Profiles ───────────────────────────────────────
@app.get('/users')
def list_users(): return jsonify(list(users.keys()))

@app.get('/users/online')
def users_online():
    return jsonify({uid: is_online(uid) for uid in users})

@app.get('/public_key/<user_id>')
def get_key(user_id): return jsonify({"public_key": users.get(user_id)})

@app.get('/profile/<user_id>')
def get_profile(user_id):
    p=profiles.get(user_id)
    if not p: return jsonify({"error":"not found"}),404
    return jsonify(p)

@app.post('/profile/<user_id>')
def set_profile(user_id):
    profiles.setdefault(user_id,{"display_name":user_id,"avatar":"🙂","status":"","theme":"dark"})
    for k in ["display_name","avatar","status","theme","is_private"]:
        if k in request.json: profiles[user_id][k]=request.json[k]
    return jsonify({"status":"ok","profile":profiles[user_id]})

@app.get('/profiles')
def get_all_profiles():
    return jsonify({uid:{"display_name":p["display_name"],"avatar":p["avatar"],"status":p["status"],"online":is_online(uid)} for uid,p in profiles.items()})

# ── Messages ───────────────────────────────────────────────
@app.post('/send')
def send():
    data    = request.json
    to      = data['to']
    sender  = data['from']
    msg_id  = str(uuid.uuid4())
    reply_to= data.get('reply_to')
    file_id = data.get('file_id')
    text    = data.get('message','')
    messages.setdefault(to,[])
    touch(sender)
    ck=chat_key(sender,to)
    chat_msgs.setdefault(ck,[])
    chat_msgs[ck].append({"id":msg_id,"from":sender,"text":text,"ts":time.time(),"read":False,"reply_to":reply_to,"file_id":file_id})
    if sender in user_keys and to in users:
        try:
            priv=b64_decode_private_key(user_keys[sender])
            rpub=b64_decode_public_key(users[to])
            payload=json.dumps({"text":text,"id":msg_id,"reply_to":reply_to,"file_id":file_id})
            ct=encrypt_message(priv,rpub,payload)
            messages[to].append({"from":sender,"ciphertext":ct,"msg_id":msg_id,"timestamp":time.time()})
        except Exception as e: print(f"Encrypt error: {e}")
    else:
        messages[to].append({"from":sender,"ciphertext":text,"msg_id":msg_id,"timestamp":time.time()})
    return jsonify({"status":"sent","msg_id":msg_id})

@app.post('/read')
def mark_read():
    uid=request.json.get('user_id',''); other=request.json.get('other','')
    touch(uid)
    ck=chat_key(uid,other)
    for m in chat_msgs.get(ck,[]):
        if m['from']==other: m['read']=True
    return jsonify({"status":"ok"})

@app.get('/read_status')
def read_status():
    uid=request.args.get('user_id',''); other=request.args.get('other','')
    if not uid or not other: return jsonify([])
    touch(uid)
    ck=chat_key(uid,other)
    return jsonify([{"id":m["id"],"read":m["read"]} for m in chat_msgs.get(ck,[]) if m["from"]==uid])

@app.get('/get_messages')
def get_messages_route():
    uid=request.args.get('user_id','')
    if not uid or uid not in user_keys: return jsonify([])
    touch(uid)
    raw=messages.get(uid,[]).copy(); messages[uid]=[]
    priv=b64_decode_private_key(user_keys[uid])
    result=[]
    for m in raw:
        try:
            spub=b64_decode_public_key(users[m['from']])
            ps=decrypt_message(priv,spub,m['ciphertext'])
            try:
                p=json.loads(ps)
                result.append({"from":m['from'],"text":p.get('text',''),"id":p.get('id',m.get('msg_id','')),"reply_to":p.get('reply_to'),"file_id":p.get('file_id')})
            except:
                result.append({"from":m['from'],"text":ps,"id":m.get('msg_id',''),"reply_to":None,"file_id":None})
        except Exception as e: print(f"Decrypt error: {e}")
    return jsonify(result)

@app.get('/chat_history')
def chat_history_route():
    uid=request.args.get('user_id',''); other=request.args.get('other','')
    if not uid or not other or uid not in user_keys: return jsonify([])
    touch(uid)
    return jsonify(chat_msgs.get(chat_key(uid,other),[]))

# ── Files ──────────────────────────────────────────────────
@app.post('/upload')
def upload_file():
    uid=request.form.get('user_id','')
    if uid not in user_keys: return jsonify({"error":"not authorized"}),401
    touch(uid)
    f=request.files.get('file')
    if not f: return jsonify({"error":"no file"}),400
    fid=str(uuid.uuid4())
    files_store[fid]={"name":f.filename,"mime":f.content_type or 'application/octet-stream',"data":base64.b64encode(f.read()).decode(),"uploaded_by":uid,"ts":time.time()}
    return jsonify({"status":"ok","file_id":fid,"name":f.filename,"mime":f.content_type})

@app.get('/file/<file_id>')
def get_file(file_id):
    meta=files_store.get(file_id)
    if not meta: return jsonify({"error":"not found"}),404
    return jsonify({"name":meta["name"],"mime":meta["mime"],"data":meta["data"]})

# ── Groups ─────────────────────────────────────────────────
@app.post('/group/create')
def create_group():
    data=request.json; uid=data.get('user_id',''); name=data.get('name','').strip()
    members=data.get('members',[])
    if uid not in user_keys or not name: return jsonify({"error":"invalid"}),400
    touch(uid)
    if uid not in members: members.append(uid)
    gid='g_'+str(uuid.uuid4())[:8]
    groups[gid]={"name":name,"avatar":data.get('avatar','👥'),"members":members,"created_by":uid,"ts":time.time()}
    group_msgs[gid]=[]
    return jsonify({"status":"ok","group_id":gid})

@app.post('/group/<gid>/send')
def group_send(gid):
    g=groups.get(gid)
    if not g: return jsonify({"error":"not found"}),404
    data=request.json; sender=data.get('from','')
    if sender not in g['members']: return jsonify({"error":"not member"}),403
    touch(sender)
    mid=str(uuid.uuid4())
    group_msgs[gid].append({"id":mid,"from":sender,"text":data.get('message',''),"ts":time.time(),"reply_to":data.get('reply_to'),"file_id":data.get('file_id')})
    return jsonify({"status":"sent","msg_id":mid})

@app.get('/group/<gid>/messages')
def group_get_msgs(gid):
    uid=request.args.get('user_id',''); g=groups.get(gid)
    if not g or uid not in g['members']: return jsonify([])
    touch(uid)
    since=float(request.args.get('since',0))
    return jsonify([m for m in group_msgs.get(gid,[]) if m['ts']>since])

@app.get('/groups')
def list_groups():
    uid=request.args.get('user_id','')
    return jsonify({gid:{"name":g["name"],"avatar":g["avatar"],"members":g["members"]} for gid,g in groups.items() if uid in g['members']})

@app.post('/group/<gid>/add')
def add_to_group(gid):
    data=request.json; uid=data.get('user_id',''); nm=data.get('member','')
    g=groups.get(gid)
    if not g or uid not in g['members']: return jsonify({"error":"forbidden"}),403
    if nm in users and nm not in g['members']: g['members'].append(nm)
    return jsonify({"status":"ok","members":g['members']})

# ── Chat Requests ──────────────────────────────────────────

@app.post('/request/send')
def send_request():
    data   = request.json
    sender = data.get('from','')
    to     = data.get('to','')
    if sender not in user_keys or to not in users:
        return jsonify({"error":"invalid"}), 400
    touch(sender)
    # Check if target is private
    tp = profiles.get(to, {})
    if not tp.get('is_private', False):
        return jsonify({"status":"not_needed"})
    # Check existing request
    existing = [r for r in chat_requests.get(to,[]) if r['from']==sender]
    if existing:
        ex = existing[0]
        if ex['status'] == 'pending':
            return jsonify({"status":"already_sent"})
        if ex['status'] == 'accepted':
            return jsonify({"status":"already_accepted"})
        if ex['status'] == 'rejected':
            # Allow resend — reset to pending
            ex['status'] = 'pending'
            ex['ts'] = time.time()
            return jsonify({"status":"resent","request_id": ex['id']})
    req_id = str(uuid.uuid4())
    chat_requests.setdefault(to, []).append({
        "id": req_id, "from": sender, "ts": time.time(), "status": "pending"
    })
    return jsonify({"status":"sent","request_id":req_id})

@app.post('/request/respond')
def respond_request():
    data   = request.json
    uid    = data.get('user_id','')
    req_id = data.get('request_id','')
    action = data.get('action','')  # accept / reject
    if uid not in user_keys: return jsonify({"error":"unauthorized"}), 401
    touch(uid)
    for r in chat_requests.get(uid, []):
        if r['id'] == req_id:
            r['status'] = 'accepted' if action == 'accept' else 'rejected'
            return jsonify({"status":"ok","action":r['status']})
    return jsonify({"error":"not found"}), 404

@app.get('/requests/incoming')
def incoming_requests():
    uid = request.args.get('user_id','')
    if uid not in user_keys: return jsonify([])
    touch(uid)
    reqs = chat_requests.get(uid, [])
    result = []
    for r in reqs:
        if r['status'] == 'pending':
            p = profiles.get(r['from'], {})
            result.append({
                "id": r['id'], "from": r['from'],
                "display_name": p.get('display_name', r['from']),
                "avatar": p.get('avatar','🙂'), "ts": r['ts']
            })
    return jsonify(result)

@app.get('/request/status')
def request_status():
    sender = request.args.get('from','')
    to     = request.args.get('to','')
    for r in chat_requests.get(to, []):
        if r['from'] == sender:
            return jsonify({"status": r['status'], "request_id": r['id']})
    return jsonify({"status":"none"})

@app.get('/chat/allowed')
def chat_allowed():
    uid   = request.args.get('user_id','')
    other = request.args.get('other','')
    tp    = profiles.get(other, {})
    if not tp.get('is_private', False):
        return jsonify({"allowed": True})
    # Check if accepted request exists
    for r in chat_requests.get(other, []):
        if r['from'] == uid and r['status'] == 'accepted':
            return jsonify({"allowed": True})
    for r in chat_requests.get(uid, []):
        if r['from'] == other and r['status'] == 'accepted':
            return jsonify({"allowed": True})
    return jsonify({"allowed": False})

# ── Channels ───────────────────────────────────────────────

@app.post('/channel/create')
def create_channel():
    data  = request.json
    uid   = data.get('user_id','')
    name  = data.get('name','').strip()
    if uid not in user_keys or not name:
        return jsonify({"error":"invalid"}), 400
    touch(uid)
    cid = 'ch_' + str(uuid.uuid4())[:8]
    channels[cid] = {
        "name": name, "avatar": data.get('avatar','📢'),
        "about": data.get('about',''), "owner": uid,
        "subscribers": [uid], "ts": time.time()
    }
    channel_posts[cid] = []
    return jsonify({"status":"ok","channel_id":cid})

@app.post('/channel/<cid>/post')
def channel_post(cid):
    ch = channels.get(cid)
    if not ch: return jsonify({"error":"not found"}), 404
    data   = request.json
    sender = data.get('from','')
    if sender != ch['owner']:
        return jsonify({"error":"only owner can post"}), 403
    touch(sender)
    pid = str(uuid.uuid4())
    channel_posts[cid].append({
        "id": pid, "from": sender,
        "text": data.get('message',''),
        "ts": time.time(), "file_id": data.get('file_id')
    })
    return jsonify({"status":"ok","post_id":pid})

@app.get('/channel/<cid>/posts')
def channel_get_posts(cid):
    ch = channels.get(cid)
    if not ch: return jsonify({"error":"not found"}), 404
    uid   = request.args.get('user_id','')
    since = float(request.args.get('since',0))
    if uid: touch(uid)
    return jsonify([p for p in channel_posts.get(cid,[]) if p['ts']>since])

@app.post('/channel/<cid>/subscribe')
def channel_subscribe(cid):
    ch  = channels.get(cid)
    uid = request.json.get('user_id','')
    if not ch or uid not in user_keys:
        return jsonify({"error":"invalid"}), 400
    touch(uid)
    if uid not in ch['subscribers']:
        ch['subscribers'].append(uid)
    return jsonify({"status":"ok"})

@app.post('/channel/<cid>/unsubscribe')
def channel_unsubscribe(cid):
    ch  = channels.get(cid)
    uid = request.json.get('user_id','')
    if ch and uid in ch['subscribers'] and uid != ch['owner']:
        ch['subscribers'].remove(uid)
    return jsonify({"status":"ok"})

@app.get('/channels')
def list_channels():
    uid = request.args.get('user_id','')
    if uid: touch(uid)
    result = {}
    for cid, ch in channels.items():
        result[cid] = {
            "name": ch['name'], "avatar": ch['avatar'],
            "about": ch['about'], "owner": ch['owner'],
            "subscribers": len(ch['subscribers']),
            "subscribed": uid in ch['subscribers'],
            "is_owner": uid == ch['owner']
        }
    return jsonify(result)

@app.get('/channel/<cid>/info')
def channel_info(cid):
    ch = channels.get(cid)
    if not ch: return jsonify({"error":"not found"}), 404
    uid = request.args.get('user_id','')
    return jsonify({
        "name": ch['name'], "avatar": ch['avatar'],
        "about": ch['about'], "owner": ch['owner'],
        "subscribers": len(ch['subscribers']),
        "subscribed": uid in ch['subscribers'],
        "is_owner": uid == ch['owner']
    })

# ── Push Notifications ──────────────────────────────────────

@app.post('/push/subscribe')
def push_subscribe():
    uid  = request.json.get('user_id','')
    sub  = request.json.get('subscription')
    if uid in user_keys and sub:
        push_tokens.setdefault(uid,[])
        if sub not in push_tokens[uid]:
            push_tokens[uid].append(sub)
    return jsonify({"status":"ok"})

@app.get('/push/vapid-key')
def vapid_key():
    # Placeholder — real VAPID needs pywebpush
    return jsonify({"key": os.environ.get("VAPID_PUBLIC_KEY","")})

# ── AI Bot ─────────────────────────────────────────────────
def groq_request(history):
    resp=requests.post(GROQ_URL,headers={"Authorization":f"Bearer {GROQ_API_KEY}","Content-Type":"application/json"},
        json={"model":GROQ_MODEL,"messages":history,"max_tokens":1024},timeout=20)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]

ai_history={}

def menu():
    return ("<b>🤖 Crypto Assistant v5.0</b><br><br><div class='bot-menu'>"
        "<button class='menu-btn' onclick='fillCmd(\"hash \")'>#️⃣ Hash</button>"
        "<button class='menu-btn' onclick='sendCmd(\"pass\")'>🔐 Pass</button>"
        "<button class='menu-btn' onclick='fillCmd(\"stego hide \")'>📦 Hide</button>"
        "<button class='menu-btn' onclick='fillCmd(\"stego reveal \")'>🔓 Reveal</button>"
        "<button class='menu-btn' onclick='fillCmd(\"encrypt \")'>📥 Enc</button>"
        "<button class='menu-btn' onclick='fillCmd(\"decrypt \")'>📤 Dec</button>"
        "<button class='menu-btn' onclick='fillCmd(\"entropy \")'>📊 Entropy</button>"
        "<button class='menu-btn' onclick='fillCmd(\"caesar enc 3 \")'>🔤 Caesar</button>"
        "<button class='menu-btn' onclick='sendCmd(\"keygen\")'>🗝️ Keygen</button>"
        "<button class='menu-btn full' onclick='sendCmd(\"info\")'>ℹ️ Info</button></div>")

def try_builtin(raw):
    t=raw.strip(); tl=t.lower()
    if tl in ["/help","help","❓","меню","/start"]: return menu()
    if tl=="info": return "🛡️ <b>Архитектура:</b><br>• E2EE<br>• Curve25519<br>• XSalsa20-Poly1305<br>• Стеганография<br>• AI: Llama 3.3 70B"
    if tl.startswith("hash "): return f"#️⃣ <b>SHA256:</b><br><code>{hashlib.sha256(t[5:].strip().encode()).hexdigest()}</code>"
    if tl.startswith("encrypt "): return f"📥 <b>Base64:</b><br><code>{base64.b64encode(t[8:].encode()).decode()}</code>"
    if tl.startswith("decrypt "):
        try: return f"📤 <b>Decoded:</b><br>{base64.b64decode(t[8:].encode()).decode()}"
        except: return "❌ Ошибка"
    if tl.startswith("entropy "):
        d=t[8:]; c=len(set(d)); e=len(d)*math.log2(c) if c>1 else len(d)
        return f"📊 <b>Энтропия:</b> {e:.2f} бит"
    if tl.startswith("stego hide "):
        s=t[11:]; b=''.join(format(ord(c),'08b') for c in s)
        return f"<b>Скрытое:</b><div class='stego-copy-box'>SAFE{''.join(chr(0x200b) if x=='0' else chr(0x200c) for x in b)}</div>"
    if tl.startswith("stego reveal "):
        bits="".join('0' if c=='\u200b' else '1' for c in t if c in['\u200b','\u200c'])
        try: return f"<b>Раскрыто:</b> <code>{''.join(chr(int(bits[i:i+8],2)) for i in range(0,len(bits),8))}</code>"
        except: return "Скрытых данных не найдено"
    if tl.startswith("caesar enc "):
        try:
            p=t.split(" ",3); sh=int(p[2])
            return f"🔤 <code>{''.join(chr((ord(c)-65+sh)%26+65) if c.isupper() else chr((ord(c)-97+sh)%26+97) if c.islower() else c for c in p[3])}</code>"
        except: return "caesar enc 3 hello"
    if tl=="pass": return f"🔐 <code>{''.join(secrets.choice(string.ascii_letters+string.digits+'!@#$%') for _ in range(16))}</code>"
    if tl=="keygen": _,pb=generate_identity_keypair(); return f"🗝️ <code>{b64_encode_key(pb)}</code>"
    return None

def ask_ai(sender, message):
    if sender not in ai_history:
        ai_history[sender]=[{"role":"system","content":SYSTEM_PROMPT}]
    ai_history[sender].append({"role":"user","content":message})
    for attempt in range(3):
        try:
            reply=groq_request(ai_history[sender])
            ai_history[sender].append({"role":"assistant","content":reply})
            if len(ai_history[sender])>21:
                ai_history[sender]=[ai_history[sender][0]]+ai_history[sender][-20:]
            return reply
        except Exception as e:
            print(f"AI попытка {attempt+1}: {e}")
            if "429" in str(e): time.sleep(5)
            else: break
    ai_history[sender].pop()
    return "⚠️ AI перегружен, попробуй через 10 сек"

def bot_loop():
    print("🤖 Бот запущен")
    while True:
        try:
            pending=messages.get(BOT_ID,[]).copy()
            if pending:
                messages[BOT_ID]=[]
                for m in pending:
                    sender=m['from']
                    if sender not in users: continue
                    try:
                        spub=b64_decode_public_key(users[sender])
                        raw=decrypt_message(bot_priv,spub,m['ciphertext'])
                        try:
                            parsed=json.loads(raw)
                            income=parsed.get('text',raw)
                            file_id=parsed.get('file_id')
                        except:
                            income=raw; file_id=None
                        # Если прислали файл — анализируем содержимое
                        if file_id and file_id in files_store:
                            meta=files_store[file_id]
                            fname=meta['name']; fmime=meta['mime']
                            fsize=len(base64.b64decode(meta['data']))
                            extracted=extract_text_from_file(meta)
                            if fmime.startswith('image/'):
                                income=(f"Пользователь прислал изображение '{fname}'. "
                                       f"Сообщи что получил изображение. Если пользователь попросит описать — скажи что для анализа изображений нужна vision-модель.")
                            elif extracted:
                                income=(f"Пользователь прислал документ '{fname}' ({fsize//1024}KB). "
                                       f"Вот его содержимое для анализа:\n\n{extracted}\n\n"
                                       f"Кратко резюмируй содержимое и спроси как ещё помочь с этим документом.")
                            else:
                                income=(f"Пользователь прислал файл '{fname}' ({fsize//1024}KB, {fmime}). "
                                       f"Сообщи что получил файл. Для глубокого анализа бинарных файлов потребуется специальная обработка.")
                        elif income=='[file]':
                            income="Пользователь прислал файл, но содержимое недоступно."
                        reply=try_builtin(income) or ask_ai(sender,income)
                        ct=encrypt_message(bot_priv,spub,json.dumps({"text":reply,"id":str(uuid.uuid4())}))
                        messages.setdefault(sender,[])
                        messages[sender].append({"from":BOT_ID,"ciphertext":ct,"msg_id":str(uuid.uuid4()),"timestamp":time.time()})
                    except Exception as e: print(f"Bot msg error: {e}")
        except Exception as e: print(f"Bot loop error: {e}")
        last_seen[BOT_ID]=time.time()
        time.sleep(1)

threading.Thread(target=bot_loop,daemon=True).start()

if __name__=='__main__':
    port=int(os.environ.get("PORT",5000))
    app.run(host='0.0.0.0',port=port)
