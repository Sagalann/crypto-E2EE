import os, json, time, base64, secrets, string, hashlib, math, threading, uuid
import requests
from flask import Flask, request, jsonify, render_template
from crypto import *

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

GROQ_API_KEY  = os.environ.get("GROQ_API_KEY", "сюда_вставь_ключ")
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
        messages[uid]=[]; profiles[uid]={"display_name":uid,"avatar":"🙂","status":"","theme":"dark"}
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
    for k in ["display_name","avatar","status","theme"]:
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
                        try: income=json.loads(raw).get('text',raw)
                        except: income=raw
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
