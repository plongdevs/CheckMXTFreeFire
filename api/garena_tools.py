import hashlib
import requests
import base64
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECRET_KEY = b"1e5898ccb8dfdd921f9bdea848768b64a201"
AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
AES_IV = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
FF_VER = "OB53"

GARENA_HEADERS = {
    "User-Agent": "GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip"
}

def decode_nickname(encoded: str) -> str:
    try:
        raw = base64.b64decode(encoded)
        dec = bytearray()
        for i, b in enumerate(raw): 
            dec.append(b ^ SECRET_KEY[i % len(SECRET_KEY)])
        return dec.decode("utf-8", errors="replace")
    except Exception: 
        return encoded

def aes_encrypt(data: bytes, key=AES_KEY, iv=AES_IV) -> bytes:
    if isinstance(key, str): key = bytes.fromhex(key) if len(key) == 32 else key.encode()
    if isinstance(iv, str):  iv  = bytes.fromhex(iv)  if len(iv)  == 32 else iv.encode()
    if isinstance(key, list) and len(key) > 0: key = key[0]
    if isinstance(iv, list) and len(iv) > 0: iv = iv[0]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def aes_decrypt(data: bytes, key=AES_KEY, iv=AES_IV) -> bytes:
    if isinstance(key, str): key = bytes.fromhex(key) if len(key) == 32 else key.encode()
    if isinstance(iv, str):  iv  = bytes.fromhex(iv)  if len(iv)  == 32 else iv.encode()
    if isinstance(key, list) and len(key) > 0: key = key[0]
    if isinstance(iv, list) and len(iv) > 0: iv = iv[0]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)

def parse_proto(data: bytes) -> dict:
    result = {}
    idx = 0
    while idx < len(data):
        try:
            tag = data[idx]; idx += 1
            fn = tag >> 3; wt = tag & 0x07
            if wt == 0:
                val = 0; shift = 0
                while idx < len(data):
                    b = data[idx]; idx += 1
                    val |= (b & 0x7F) << shift
                    if not (b & 0x80): break
                    shift += 7
                if fn in result:
                    if not isinstance(result[fn], list): result[fn] = [result[fn]]
                    result[fn].append(val)
                else: result[fn] = val
            elif wt == 2:
                ln = 0; shift = 0
                while idx < len(data):
                    b = data[idx]; idx += 1
                    ln |= (b & 0x7F) << shift
                    if not (b & 0x80): break
                    shift += 7
                vb = data[idx:idx+ln]; idx += ln
                if fn in result:
                    if not isinstance(result[fn], list): result[fn] = [result[fn]]
                    result[fn].append(vb)
                else: result[fn] = vb
            elif wt == 1:
                idx += 8
            elif wt == 5:
                idx += 4
            else: break
        except: break
    return result

def decode_jwt(token: str) -> dict:
    import json
    parts = token.split(".")
    if len(parts) < 2: return {}
    p = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(p).decode())
        if "nickname" in payload and isinstance(payload["nickname"], str):
            payload["nickname"] = decode_nickname(payload["nickname"])
        return payload
    except: return {}

def convert_time(seconds):
    d, s = divmod(int(seconds), 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return f"{d}d {h}h {m}m {s}s"

def send_otp(email, access_token):
    url = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
    data = {"email": email, "locale": "en_MA", "region": "IND",
            "app_id": "100067", "access_token": access_token}
    try:
        return requests.post(url, headers=GARENA_HEADERS, data=data)
    except Exception as e:
        return None

def verify_otp(otp, email, access_token):
    url = "https://100067.connect.garena.com/game/account_security/bind:verify_otp"
    data = {"app_id": "100067", "access_token": access_token, "otp": otp, "email": email}
    return requests.post(url, data=data, headers=GARENA_HEADERS)

def cancel_request(access_token):
    url = "https://100067.connect.garena.com/game/account_security/bind:cancel_request"
    payload = {'app_id': "100067", 'access_token': access_token}
    try: 
        requests.post(url, data=payload, headers=GARENA_HEADERS)
    except: 
        pass

def create_bind_request(verifier_token, access_token, email, security_code):
    cancel_request(access_token)
    hashed_password = hashlib.sha256(security_code.encode('utf-8')).hexdigest().upper()
    url = "https://100067.connect.garena.com/game/account_security/bind:create_bind_request"
    data = {
        "app_id": "100067",
        "access_token": access_token,
        "verifier_token": verifier_token,
        "secondary_password": hashed_password,
        "email": email
    }
    resp = requests.post(url, data=data, headers=GARENA_HEADERS)
    return resp

def add_recovery_email(email, access_token, otp, security_code):
    resp = send_otp(email, access_token)
    if not resp or resp.status_code != 200:
        return {"success": False, "message": "Failed to send OTP"}
    
    vr = verify_otp(otp, email, access_token)
    if vr.status_code != 200:
        return {"success": False, "message": "OTP verification failed"}
    
    verifier_token = vr.json().get("verifier_token")
    if not verifier_token:
        return {"success": False, "message": "No verifier token"}
    
    br = create_bind_request(verifier_token, access_token, email, security_code)
    if br.status_code == 200:
        return {"success": True, "message": f"Email {email} added successfully!"}
    else:
        return {"success": False, "message": f"Failed: {br.text}"}

def check_recovery_email(access_token):
    url = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info"
    try:
        resp = requests.get(url, params={'app_id': "100067", 'access_token': access_token}, headers=GARENA_HEADERS)
        if resp.status_code == 200:
            data = resp.json()
            email = data.get("email", "")
            email_to_be = data.get("email_to_be", "")
            countdown = data.get("request_exec_countdown", 0)
            
            if email == "" and email_to_be != "":
                return {
                    "success": True,
                    "email": None,
                    "pending_email": email_to_be,
                    "countdown": convert_time(countdown),
                    "status": "pending"
                }
            elif email != "":
                return {
                    "success": True,
                    "email": email,
                    "pending_email": None,
                    "countdown": None,
                    "status": "verified"
                }
            else:
                return {
                    "success": True,
                    "email": None,
                    "pending_email": None,
                    "countdown": None,
                    "status": "none"
                }
        else:
            return {"success": False, "message": f"API Error: {resp.status_code}"}
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}

def check_platforms(access_token):
    url = "https://100067.connect.garena.com/bind/app/platform/info/get"
    try:
        resp = requests.get(url, params={'access_token': access_token}, headers=GARENA_HEADERS)
        if resp.status_code not in [200, 201]:
            return {"success": False, "message": "Failed to fetch platform data"}
        
        platform_names = {3:"Facebook", 8:"Gmail", 10:"Apple", 5:"VK", 11:"Twitter (X)", 7:"Huawei"}
        data = resp.json()
        bounded = data.get("bounded_accounts", [])
        available = data.get("available_platforms", [])
        
        secondary_links = []
        for acc in bounded:
            try:
                platform = acc.get('platform')
                ui = acc.get('user_info', {})
                email = ui.get('email', '')
                nick  = ui.get('nickname', '')
                if platform in platform_names:
                    secondary_links.append({
                        "platform": platform_names[platform],
                        "email": email,
                        "nickname": nick
                    })
            except: 
                continue
        
        main_platform = None
        for pid, name in platform_names.items():
            if pid not in available:
                main_platform = name
                break
        
        return {
            "success": True,
            "secondary_links": secondary_links,
            "main_platform": main_platform
        }
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}

def cancel_recovery_email(access_token):
    url = "https://100067.connect.garena.com/game/account_security/bind:cancel_request"
    try:
        resp = requests.post(url, data={'app_id': "100067", 'access_token': access_token}, headers=GARENA_HEADERS)
        if resp.status_code == 200:
            return {"success": True, "message": "Cancelled successfully", "data": resp.json()}
        else:
            return {"success": False, "message": "No active request found"}
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}

def revoke_token(access_token):
    try:
        resp = requests.get(f"https://100067.connect.garena.com/oauth/logout?access_token={access_token}")
        if resp.text.strip() == '{"result":0}':
            return {"success": True, "message": "Token revoked!"}
        else:
            return {"success": False, "message": f"Failed: {resp.text}"}
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}

def extract_eat_from_input(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith('http'):
        m = re.search(r'[?&]eat=([a-fA-F0-9]+)', raw)
        if m: return m.group(1)
    return raw

def eat_to_access(eat_token: str) -> str:
    TARGET = "https://api-otrss.garena.com/support/callback/"
    session = requests.Session()
    resp = session.get(TARGET, params={'access_token': eat_token}, allow_redirects=False)
    while resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get('Location', '')
        if not location: break
        if not location.startswith(('http://', 'https://')):
            base = urlparse(TARGET)
            location = base._replace(path=location).geturl()
        resp = session.get(location, allow_redirects=False)
    parsed = urlparse(resp.url)
    params = parse_qs(parsed.query)
    return params.get('access_token', [None])[0]

def _varint(v):
    r = bytearray()
    while v > 0x7F:
        r.append((v & 0x7F) | 0x80); v >>= 7
    r.append(v); return bytes(r)

def _int_field(f, v):
    return _varint((f << 3) | 0) + _varint(v)

def _msg_field(f, v_bytes):
    return _varint((f << 3) | 2) + _varint(len(v_bytes)) + v_bytes

def _str_field(f, v):
    if isinstance(v, str): v = v.encode()
    return _varint((f << 3) | 2) + _varint(len(v)) + v

def build_login_payload(open_id: str, access_token: str, platform: int) -> bytes:
    now = str(datetime.now())[:19]
    pl = bytearray()
    pl += _str_field(3,  now)
    pl += _str_field(22, open_id)
    pl += _str_field(23, str(platform))
    pl += _str_field(29, access_token)
    pl += _str_field(99, str(platform))
    return bytes(pl)

def inspect_token(access_token: str):
    url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
    h = {"Connection": "close", "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)"}
    r = requests.get(url, headers=h, timeout=10)
    d = r.json()
    if 'error' in d: 
        raise Exception(f"Token lỗi: {d.get('error')}")
    return d.get('open_id'), int(d.get('platform', 8))

def do_major_login(open_id: str, access_token: str, platform: int):
    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    headers = {
        'X-Unity-Version': '2018.4.11f1', 'ReleaseVersion': FF_VER,
        'Content-Type': 'application/x-www-form-urlencoded', 'X-GA': 'v1 1',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'loginbp.ggpolarbear.com',
        'Connection': 'Keep-Alive'
    }
    enc = aes_encrypt(build_login_payload(open_id, access_token, platform))
    resp = requests.post(url, headers=headers, data=enc, verify=False, timeout=10)
    if resp.status_code != 200:
        raise Exception(f"MajorLogin thất bại HTTP {resp.status_code}")
    
    content = resp.content
    
    for data_to_parse in [content, (lambda: (aes_decrypt(content) if len(content)%16==0 else b""))()]:
        if not data_to_parse: continue
        parsed = parse_proto(data_to_parse)
        token = parsed.get(8)
        if isinstance(token, list): token = token[0]
        if token:
            if isinstance(token, bytes): token = token.decode('utf-8', 'ignore')
            key = parsed.get(22, AES_KEY)
            if isinstance(key, list): key = key[0]
            iv = parsed.get(23, AES_IV)
            if isinstance(iv, list): iv = iv[0]
            return token, key, iv
            
    raise Exception("Không parse được JWT từ MajorLogin")

def access_to_jwt(access_token: str):
    open_id, platform = inspect_token(access_token)
    for pt in [platform, 2, 3, 4, 6, 8]:
        try:
            jwt, key, iv = do_major_login(open_id, access_token, pt)
            if jwt: return jwt
        except Exception as e:
            continue
    raise Exception("Tất cả platform đều thất bại")

def eat_to_jwt(eat_token: str):
    access = eat_to_access(eat_token)
    if not access:
        raise Exception("Không lấy được Access Token")
    open_id, platform = inspect_token(access)
    jwt, _, _ = do_major_login(open_id, access, platform)
    return jwt

def guest_get_access(uid, password):
    url = "https://100067.connect.garena.com/oauth/token"
    data = {
        'grant_type': 'password',
        'app_id': '100067',
        'account': uid,
        'password': hashlib.md5(password.encode()).hexdigest()
    }
    headers = {
        'User-Agent': 'GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    try:
        r = requests.post(url, data=data, headers=headers, timeout=12)
        j = r.json()
        return j.get('open_id'), j.get('access_token')
    except Exception as e:
        return None, None

def guest_to_jwt(uid, password):
    open_id, access_token = guest_get_access(uid, password)
    if not open_id or not access_token:
        raise Exception("Guest auth thất bại")
    jwt, _, _ = do_major_login(open_id, access_token, 4)
    return jwt