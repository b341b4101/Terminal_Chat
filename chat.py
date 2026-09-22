"""Hardened LAN chat: bounded control frames and chunked, encrypted file streaming."""
import hashlib, hmac, json, os, secrets, shlex, shutil, socket, struct, sys, tempfile, threading, time, zipfile
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DISCOVERY_PORT=5001; DISCOVERY_REQUEST=b"CHAT_DISCOVER_V2"; DISCOVERY_PREFIX="CHAT_HERE_V2"
FRAME_MAX=1024*1024; CHUNK=64*1024; TEXT_MAX=256*1024; SALT_SIZE=16
PROTOCOL_VERSION=2; SOCKET_TIMEOUT=30; HEARTBEAT_SECONDS=15
GLOBAL_PORT=52731; GLOBAL_PASSWORD="open-world-chat-fixed"; CONFIG_FILE="config.txt"
MAX_FILE_SIZE=2*1024*1024*1024
MAX_ROOM_STORAGE=8*1024*1024*1024
class QuitProgram(Exception): pass

ANSI={"system":"\\033[36m","error":"\\033[31m","private":"\\033[35m","file":"\\033[33m","reset":"\\033[0m"}
def colorize(text,kind="system"):
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"): return text
    return ANSI.get(kind,"")+text+ANSI["reset"]
def notify():
    if os.environ.get("CHAT_NO_NOTIFY"): return
    try:
        if os.name=="nt":
            import winsound; winsound.MessageBeep()
        else: print("\\a",end="",flush=True)
    except Exception: pass
def config_save(config,path=CONFIG_FILE):
    try:
        with open(path,"w",encoding="utf8") as f:
            for k,v in config.items(): f.write(f"{k}={v}\n")
    except OSError: pass

COMMANDS=["/upload","/download","/who","/msg","/history","/typing","/kick","/ban","/unban","/mute","/unmute","/help","/exit","/quit"]
def setup_completion():
    try:
        import readline
        def complete(text,state):
            options=[c for c in COMMANDS if c.startswith(text)]
            return options[state] if state<len(options) else None
        readline.set_completer(complete); readline.parse_and_bind("tab: complete")
    except (ImportError,AttributeError):
        pass

def clear_terminal():
    """Clear old output without clearing messages while a room is active."""
    command = "cls" if os.name == "nt" else "clear"
    os.system(command)


def key_from_password(password,salt):
    if len(salt)<SALT_SIZE: raise ValueError("invalid room salt")
    return PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=480000).derive(password.encode())

def send_frame(sock,data,lock=None):
    if len(data)>FRAME_MAX: raise ValueError("frame too large")
    packet=struct.pack(">I",len(data))+data
    with lock if lock else _NullLock(): sock.sendall(packet)

def receive_exact(sock,n):
    if n<0 or n>FRAME_MAX: raise ValueError("invalid frame length")
    out=bytearray()
    while len(out)<n:
        part=sock.recv(min(CHUNK,n-len(out)))
        if not part:return None
        out.extend(part)
    return bytes(out)

def receive_frame(sock):
    h=receive_exact(sock,4)
    return None if h is None else receive_exact(sock,struct.unpack(">I",h)[0])

def authenticate_server(sock,key):
    """Prove possession of the room password before accepting encrypted chat data."""
    challenge=secrets.token_bytes(32)
    send_frame(sock,b"CHAT_AUTH_1"+challenge)
    proof=receive_frame(sock)
    expected=hmac.new(key,b"client"+challenge,hashlib.sha256).digest()
    if proof is None or not hmac.compare_digest(proof,expected):
        raise ValueError("room authentication failed")
    send_frame(sock,b"CHAT_AUTH_2"+hmac.new(key,b"server"+challenge,hashlib.sha256).digest())

def authenticate_client(sock,key):
    hello=receive_frame(sock)
    if hello is None or len(hello)!=43 or not hello.startswith(b"CHAT_AUTH_1"):
        raise ValueError("invalid server authentication challenge")
    challenge=hello[11:]
    send_frame(sock,hmac.new(key,b"client"+challenge,hashlib.sha256).digest())
    reply=receive_frame(sock)
    expected=b"CHAT_AUTH_2"+hmac.new(key,b"server"+challenge,hashlib.sha256).digest()
    if reply is None or not hmac.compare_digest(reply,expected):
        raise ValueError("server authentication failed")
class _NullLock:
    def __enter__(self): return self
    def __exit__(self,*args): pass

def encrypt(aes,text):
    raw=text.encode();
    if len(raw)>TEXT_MAX: raise ValueError("message too large")
    nonce=os.urandom(12); return nonce+aes.encrypt(nonce,raw,None)
def decrypt(aes,data):
    if len(data)<28: raise ValueError("encrypted message too short")
    return aes.decrypt(data[:12],data[12:],None).decode()
def enc_chunk(aes,data):
    nonce=os.urandom(12); return nonce+aes.encrypt(nonce,data,None)
def dec_chunk(aes,data):
    if len(data)<28: raise ValueError("encrypted chunk too short")
    return aes.decrypt(data[:12],data[12:],None)
def send_text(sock,aes,text,lock=None): send_frame(sock,encrypt(aes,text),lock)
def safe_name(name):
    name=os.path.basename(str(name)).replace("\0","").replace("|","_").replace("\r","_").replace("\n","_").strip()
    return (name or "file")[:255]

def clean_path(p):
    p=p.strip(); p=p[1:].strip() if p.startswith("&") else p
    return p[1:-1] if len(p)>1 and p[0]==p[-1] and p[0] in "'\"" else p
def paths(raw):
    raw=raw.strip()
    if not raw:return []
    if '"' in raw or "'" in raw:
        lx=shlex.shlex(raw,posix=False); lx.whitespace_split=True
        try:return [clean_path(x) for x in lx if clean_path(x)]
        except ValueError:return [clean_path(raw)]
    if ";" in raw:return [clean_path(x) for x in raw.split(";") if clean_path(x)]
    p=[clean_path(x) for x in raw.split() if clean_path(x)]
    return p if len(p)>1 and all(os.path.exists(x) for x in p) else [clean_path(raw)]
def download_args(raw):
    try:
        lx=shlex.shlex(raw.strip(),posix=False); lx.whitespace_split=True; p=[clean_path(x) for x in lx]
    except ValueError:p=raw.split(None,1)
    return (p[0],p[1] if len(p)>1 else ".") if p else ("",".")

def upload_source(path):
    path=os.path.abspath(path)
    if os.path.isfile(path):return safe_name(os.path.basename(path)),os.path.getsize(path),path,False
    if not os.path.isdir(path):return None
    f=tempfile.NamedTemporaryFile(delete=False,suffix=".zip"); f.close()
    try:
        with zipfile.ZipFile(f.name,"w",zipfile.ZIP_DEFLATED) as z:
            base=safe_name(os.path.basename(os.path.normpath(path)))
            for root,_dirs,names in os.walk(path):
                for name in names:z.write(os.path.join(root,name),os.path.join(base,os.path.relpath(os.path.join(root,name),path)))
        return base+".zip",os.path.getsize(f.name),f.name,True
    except Exception:
        try:os.unlink(f.name)
        except OSError:pass
        raise

def target(name,directory):
    try:os.makedirs(directory,exist_ok=True)
    except OSError:directory="."
    base=os.path.join(directory,"received_"+safe_name(name)); stem,ext=os.path.splitext(base); out=base; i=1
    while os.path.exists(out):out=f"{stem}_{i}{ext}"; i+=1
    return out

DEFAULT={"port":"5000","max_members":"10","room_name":"Chat-Room","password":"","nickname":"","room_salt":"","max_file_size_mb":"2048","max_room_storage_mb":"8192","download_dir":"."}
def config_load(path=CONFIG_FILE):
    c=DEFAULT.copy()
    if os.path.exists(path):
        try:
            with open(path,encoding="utf8") as f:
                for line in f:
                    if "=" in line and not line.lstrip().startswith("#"):
                        k,v=line.strip().split("=",1)
                        if k in c:c[k]=v
        except OSError:pass
    else:
        config_save(c,path)
    try:
        c["port"]=int(c["port"]); c["max_members"]=int(c["max_members"])
        c["max_file_size_mb"]=int(c["max_file_size_mb"]); c["max_room_storage_mb"]=int(c["max_room_storage_mb"])
    except ValueError:
        c["port"],c["max_members"],c["max_file_size_mb"],c["max_room_storage_mb"]=5000,10,2048,8192
    if not 1024<=c["port"]<=65535 or c["max_members"]<1:c["port"],c["max_members"]=5000,10
    if not 1<=c["max_file_size_mb"]<=2048:c["max_file_size_mb"]=2048
    if not 1<=c["max_room_storage_mb"]<=8192:c["max_room_storage_mb"]=8192
    try:salt=bytes.fromhex(c["room_salt"])
    except ValueError:salt=b""
    if len(salt)<SALT_SIZE:
        salt=secrets.token_bytes(SALT_SIZE); c["room_salt"]=salt.hex()
        config_save(c,path)
    return c

class Room:
    def __init__(self,max_file_size=MAX_FILE_SIZE,max_storage=MAX_ROOM_STORAGE):
        self.clients={}; self.files={}; self.history=[]; self.next=1; self.muted=set(); self.banned=set(); self.max_file_size=max_file_size; self.max_storage=max_storage; self.lock=threading.Lock(); self.file_lock=threading.Lock(); self.stop=threading.Event(); self.tmp=tempfile.mkdtemp(prefix="chat_")
    def close(self):self.stop.set(); shutil.rmtree(self.tmp,ignore_errors=True)
def broadcast(room,aes,text,skip=None):
    with room.lock: recipients=[(s,x["send"]) for s,x in room.clients.items() if s is not skip]
    for s,l in recipients:
        try:send_text(s,aes,text,l)
        except (OSError,ValueError):pass

def discovery(room_name,port,kind,salt_hex,stop):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.settimeout(.5)
    try:s.bind(("",DISCOVERY_PORT))
    except OSError: s.close(); return
    try:
        while not stop.is_set():
            try:data,addr=s.recvfrom(1024)
            except socket.timeout:continue
            if data==DISCOVERY_REQUEST:
                try:s.sendto(f"{DISCOVERY_PREFIX}|{room_name[:80]}|{port}|{kind}|{salt_hex}".encode(),addr)
                except OSError:break
    finally:s.close()
def find_servers(timeout=2):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); found=[]
    try:
        s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1); s.sendto(DISCOVERY_REQUEST,("<broadcast>",DISCOVERY_PORT)); end=time.monotonic()+timeout
        while time.monotonic()<end:
            s.settimeout(max(.05,end-time.monotonic()))
            try:data,addr=s.recvfrom(2048)
            except socket.timeout:break
            p=data.decode(errors="ignore").split("|")
            if len(p)!=5 or p[0]!=DISCOVERY_PREFIX:continue
            try:port=int(p[2]); salt=bytes.fromhex(p[4])
            except ValueError:continue
            if 1024<=port<=65535 and len(salt)>=SALT_SIZE:
                item=(addr[0],p[1],port,p[3],p[4]);
                if item not in found:found.append(item)
    except OSError:pass
    finally:s.close()
    return found

def receive_upload(sock,aes,size,path):
    got=0; digest=hashlib.sha256()
    with open(path,"wb") as out:
        while got<size:
            frame=receive_frame(sock)
            if frame is None:raise ConnectionError("upload interrupted")
            data=dec_chunk(aes,frame)
            if not data or got+len(data)>size:raise ValueError("declared file size does not match data")
            out.write(struct.pack(">I",len(frame))+frame); digest.update(data); got+=len(data)
    if got!=size:raise ValueError("file size mismatch")
    return digest.hexdigest()
def send_stored(sock,aes,entry,lock):
    send_text(sock,aes,json.dumps({"type":"file_begin","name":entry["name"],"size":entry["size"],"sha256":entry.get("sha256","")}),lock)
    with open(entry["path"],"rb") as f:
        while True:
            h=f.read(4)
            if not h:break
            n=struct.unpack(">I",h)[0]
            if n>FRAME_MAX:raise ValueError("bad stored chunk")
            b=f.read(n)
            if len(b)!=n:raise ValueError("truncated stored file")
            send_frame(sock,b,lock)
    send_text(sock,aes,json.dumps({"type":"file_end"}),lock)

def room_stamp(): return time.strftime("%Y-%m-%d %H:%M:%S")
def room_message(nick,text): return f"[{room_stamp()}] {nick}: {text}"
def handler(sock,addr,aes,room,max_members,host):
    send=threading.Lock(); nick=None
    sock.settimeout(SOCKET_TIMEOUT)
    try:
        raw=receive_frame(sock); nick=decrypt(aes,raw).strip() if raw else ""
        if not 1<=len(nick)<=32 or "|" in nick or "\n" in nick:raise ValueError("invalid nickname")
        with room.lock:
            if nick in room.banned:send_text(sock,aes,"SERVER: You are banned from this room.",send);return
            if max_members is not None and len(room.clients)>=max_members:send_text(sock,aes,"SERVER: Group is full.",send);return
            if nick==host or any(x["nick"]==nick for x in room.clients.values()):send_text(sock,aes,"SERVER: Nickname is taken.",send);return
            room.clients[sock]={"nick":nick,"send":send}
        send_text(sock,aes,"__NICK_OK__",send); broadcast(room,aes,f"[{room_stamp()}] [{nick} joined the group]",sock)
        while not room.stop.is_set():
            try: raw=receive_frame(sock)
            except socket.timeout: raise ConnectionError("client heartbeat timed out")
            if raw is None:break
            text=decrypt(aes,raw)
            if text=="__PING__":send_text(sock,aes,"__PONG__",send);continue
            if text=="__WHO__":
                with room.lock: names=[host]+[x["nick"] for x in room.clients.values()]
                send_text(sock,aes,"SERVER: Online: "+", ".join(names),send);continue
            if text=="__HISTORY__":
                with room.lock: history=list(room.history)
                send_text(sock,aes,"SERVER: Recent messages:\n"+("\n".join(history) if history else "(none)"),send);continue
            if text.startswith("__TYPING__|"):
                status=text.split("|",1)[1]
                broadcast(room,aes,f"[typing] {nick} {'is typing' if status=='on' else 'stopped typing'}",sock);continue
            if text.startswith("__MOD__|"):
                action,target_name=text[8:].split("|",1) if "|" in text[8:] else ("","")
                if nick!=host:send_text(sock,aes,"SERVER: Only the host can moderate the room.",send);continue
                with room.lock:
                    target_socket=next((s for s,x in room.clients.items() if x["nick"]==target_name),None)
                    if action=="ban":room.banned.add(target_name)
                    elif action=="unban":room.banned.discard(target_name)
                    elif action=="mute":room.muted.add(target_name)
                    elif action=="unmute":room.muted.discard(target_name)
                if action in ("kick","ban") and target_socket:
                    label="kicked" if action=="kick" else "banned"
                    send_text(target_socket,aes,f"SERVER: You were {label} by the host.",room.clients[target_socket]["send"])
                    try:target_socket.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
                send_text(sock,aes,f"SERVER: {action} applied to {target_name}.",send);continue
            if nick in room.muted:
                send_text(sock,aes,"SERVER: You are muted.",send);continue
            if text.startswith("__MSG__|"):
                target_name,message=text[8:].split("|",1) if "|" in text[8:] else ("","")
                with room.lock: recipient=next(((s,x["send"]) for s,x in room.clients.items() if x["nick"]==target_name),None)
                if recipient: send_text(recipient[0],aes,f"[private {nick} -> you] {message}",recipient[1])
                else: send_text(sock,aes,"SERVER: Nickname not found.",send)
                continue
            if text=="__LIST__":send_text(sock,aes,files_text(room),send);continue
            if text.startswith("__GET__|"):
                n=text.split("|",1)[1]
                with room.file_lock: entries=list(room.files.values()) if n=="-a" else [room.files.get(int(n))] if n.isdigit() else []
                if not entries or any(x is None for x in entries):send_text(sock,aes,"SERVER: Invalid file number.",send);continue
                for e in entries:send_stored(sock,aes,e,send)
                continue
            if text.startswith("__UPLOAD__|"):
                m=json.loads(text[11:]); name=safe_name(m.get("name")); size=m.get("size")
                if not isinstance(size,int) or size<0 or size>room.max_file_size:raise ValueError("file exceeds the room file-size limit")
                with room.file_lock:
                    if sum(x["size"] for x in room.files.values())+size>room.max_storage:raise ValueError("room storage limit reached")
                p=os.path.join(room.tmp,secrets.token_hex(16)); digest=receive_upload(sock,aes,size,p)
                with room.file_lock:n=room.next;room.next+=1;room.files[n]={"name":name,"size":size,"sha256":digest,"from":nick,"path":p}
                send_text(sock,aes,f"SERVER: File uploaded as number {n}.",send);broadcast(room,aes,f"[New file available: {name} - see /download]",sock);continue
            with room.lock:
                room.history.append(room_message(nick,text))
                room.history=room.history[-100:]
            broadcast(room,aes,room_message(nick,text),sock)
    except (InvalidTag,ValueError,UnicodeError,json.JSONDecodeError,OSError,ConnectionError):pass
    finally:
        if nick:
            with room.lock:room.clients.pop(sock,None)
            broadcast(room,aes,f"[{room_stamp()}] [{nick} left the group]",sock)
        try:sock.close()
        except OSError:pass

def files_text(room):
    with room.file_lock:
        return "SERVER: No files available for download." if not room.files else "SERVER: Available files:\n"+"\n".join(f"[{n}] - {x['name']} ({x['size']} bytes, from {x['from']})" for n,x in sorted(room.files.items()))
def store_local(aes,source,dest):
    digest=hashlib.sha256()
    with open(source,"rb") as a,open(dest,"wb") as b:
        while data:=a.read(CHUNK):
            digest.update(data); frame=enc_chunk(aes,data);b.write(struct.pack(">I",len(frame))+frame)
    return digest.hexdigest()
def server_upload(aes,room,nick,path):
    x=upload_source(path)
    if not x:print(f"[Not found: {path}]");return
    name,size,source,cleanup=x
    if size>room.max_file_size or sum(e["size"] for e in room.files.values())+size>room.max_storage:
        print("[File rejected: room file-size or storage limit exceeded]");
        if cleanup:
            try:os.unlink(source)
            except OSError:pass
        return
    dest=os.path.join(room.tmp,secrets.token_hex(16))
    try:digest=store_local(aes,source,dest);room.files[room.next]={"name":name,"size":size,"sha256":digest,"from":nick,"path":dest};room.next+=1;print(f"[Stored {name} ({size} bytes)]");broadcast(room,aes,f"[{room_stamp()}] [New file available: {name} - see /download]")
    finally:
        if cleanup:
            try:os.unlink(source)
            except OSError:pass

def save_file(aes,entry,directory):
    out=target(entry["name"],directory)
    try:
        with open(entry["path"],"rb") as a,open(out,"wb") as b:
            while h:=a.read(4):
                n=struct.unpack(">I",h)[0]; blob=a.read(n)
                if n>FRAME_MAX or len(blob)!=n:raise ValueError("bad stored file")
                b.write(dec_chunk(aes,blob))
        print(f"[Saved as '{out}']")
    except (OSError,ValueError,InvalidTag) as e:
        try:os.unlink(out)
        except OSError:pass
        print(f"[Download failed: {e}]")

def server_download(aes,room,n,d):
    with room.file_lock:es=list(room.files.values()) if n=="-a" else [room.files.get(int(n))] if n.isdigit() else []
    if not es or any(e is None for e in es):print("[Invalid file number]");return
    for e in es:save_file(aes,e,d)

HELP="/upload <path> | /download [n] [folder] | /who | /msg <nick> <text> | /history | /typing on|off | /kick /ban /unban /mute /unmute <nick> | /help | /exit | /quit"
def run_server():
    first_run=not os.path.exists(CONFIG_FILE); c=config_load()
    if first_run:
        print("First-run setup: choose a room name and password. Leave password empty for an open room.")
        c["room_name"]=input(f"Room name [{c['room_name']}]: ").strip() or c["room_name"]
        c["password"]=input("Room password (empty = open room): ")
        c["nickname"]=input("Your nickname [Server]: ").strip() or "Server"
        config_save(c)
    password=c["password"]; kind="global" if not password else "private"; password=password or GLOBAL_PASSWORD
    salt=bytes.fromhex(c["room_salt"]); key=key_from_password(password,salt); nick=c["nickname"] or input("Your nickname: ").strip() or "Server";aes=AESGCM(key);room=Room(c["max_file_size_mb"]*1024*1024,c["max_room_storage_mb"]*1024*1024);server=socket.socket();server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    try:server.bind(("",c["port"]));server.listen(20)
    except OSError as e:print(e);room.close();return
    threading.Thread(target=discovery,args=(c["room_name"] or "Chat-Room",c["port"],kind,c["room_salt"],room.stop),daemon=True).start()
    def accept():
        while not room.stop.is_set():
            s=None
            try:
                s,a=server.accept(); s.settimeout(10); authenticate_server(s,key)
            except (OSError,ValueError):
                if s is not None:
                    try:s.close()
                    except OSError:pass
                if room.stop.is_set():break
                continue
            threading.Thread(target=handler,args=(s,a,aes,room,None if kind=="global" else c["max_members"],nick),daemon=True).start()
    threading.Thread(target=accept,daemon=True).start(); clear_terminal(); setup_completion(); print(f"Room running on {c['port']}. Commands: {HELP}")
    try:
        while True:
            line=input("You: ")
            if line=="/quit":raise QuitProgram()
            if line=="/exit":break
            if line=="/help":print(HELP);continue
            if line.startswith("/upload "):
                for p in paths(line[9:]):server_upload(aes,room,nick,p)
            elif line=="/download":print(files_text(room))
            elif line=="/who":
                with room.lock:print("Online: "+", ".join([nick]+[x["nick"] for x in room.clients.values()]))
            elif line=="/history":
                with room.lock:print("\n".join(room.history[-100:]) or "(none)")
            elif line.startswith("/download "):
                n,d=download_args(line[10:]);server_download(aes,room,n,d)
            else:broadcast(room,aes,room_message(nick,line))
    except EOFError:pass
    finally:room.close();server.close()

def client_receive(sock,aes,state):
    try:
        while True:
            raw=receive_frame(sock)
            if raw is None:return
            msg=decrypt(aes,raw)
            if msg=="__PONG__":continue
            if msg.startswith('{"type":"file_begin"'):
                m=json.loads(msg);size=m["size"]; expected_hash=m.get("sha256","")
                if not isinstance(size,int) or size<0:raise ValueError("bad file size")
                out=target(m["name"],state["dir"]); temp=out+".part";got=0;digest=hashlib.sha256()
                try:
                    with open(temp,"wb") as f:
                        while got<size:
                            b=receive_frame(sock);data=dec_chunk(aes,b)
                            if not data or got+len(data)>size:raise ValueError("file size mismatch")
                            f.write(data);digest.update(data);got+=len(data)
                        if json.loads(decrypt(aes,receive_frame(sock))).get("type")!="file_end":raise ValueError("missing terminator")
                    if expected_hash and not hmac.compare_digest(digest.hexdigest(),expected_hash):raise ValueError("checksum mismatch")
                    os.replace(temp,out)
                except Exception:
                    try:os.unlink(temp)
                    except OSError:pass
                    raise
                print(f"\n[Saved as '{out}']\nYou: ",end="")
            else:
                kind="private" if msg.startswith("[private ") else "system" if msg.startswith("SERVER:") or msg.startswith("[") else "message"
                print(f"\r{colorize(msg,kind)}\nYou: ",end="")
                if not msg.startswith("[typing]"):notify()
    except (InvalidTag,ValueError,UnicodeError,OSError,ConnectionError,TypeError) as e:print(f"\n[Connection closed: {e}]")
def client_upload(sock,aes,lock,path):
    x=upload_source(path)
    if not x:print(f"[Not found: {path}]");return
    name,size,source,cleanup=x
    try:
        send_text(sock,aes,"__UPLOAD__|"+json.dumps({"name":name,"size":size}),lock)
        sent=0
        with open(source,"rb") as f:
            while data:=f.read(CHUNK):
                send_frame(sock,enc_chunk(aes,data),lock); sent+=len(data)
                if sent==size or sent%(CHUNK*16)<len(data):print(f"\r[Uploading {name}: {sent}/{size} bytes]",end="",flush=True)
        print()
    finally:
        if cleanup:
            try:os.unlink(source)
            except OSError:pass

def run_client():
    found=find_servers();
    if found:
        for i,x in enumerate(found,1):print(i,x[1],x[0],x[2],x[3])
        ch=input("Server number (Enter=manual): ").strip()
        if ch.isdigit() and 1<=int(ch)<=len(found):ip,_r,port,kind,shex=found[int(ch)-1]
        else:ip=input("IP: ").strip() or "127.0.0.1";port=int(input("Port [5000]: ") or 5000);kind="private";shex=input("Room salt hex: ")
    else:ip=input("IP: ").strip() or "127.0.0.1";port=int(input("Port [5000]: ") or 5000);kind="private";shex=input("Room salt hex: ")
    try:salt=bytes.fromhex(shex);password=GLOBAL_PASSWORD if kind=="global" else input("Room password: ");key=key_from_password(password,salt);aes=AESGCM(key)
    except ValueError:print("[Invalid salt]");return
    lock=threading.Lock();sock=None; client_config=config_load()
    try:
        sock=socket.create_connection((ip,port),10); authenticate_client(sock,key_from_password(password,salt)); send_text(sock,aes,client_config["nickname"] or input("Nickname: ").strip() or "Guest",lock);reply=receive_frame(sock)
        if decrypt(aes,reply)!="__NICK_OK__":print(decrypt(aes,reply));sock.close();return
    except (OSError,InvalidTag,ValueError,UnicodeError) as e:print(f"[Connection failed: {e}]");return
    state={"dir":client_config.get("download_dir") or ".","stop":threading.Event()}; clear_terminal(); setup_completion(); print(f"Connected to {ip}:{port}. File and message history starts here."); threading.Thread(target=client_receive,args=(sock,aes,state),daemon=True).start()
    def heartbeat():
        while not state["stop"].wait(HEARTBEAT_SECONDS):
            try:send_text(sock,aes,"__PING__",lock)
            except OSError:return
    threading.Thread(target=heartbeat,daemon=True).start()
    try:
        while True:
            line=input("You: ")
            if line=="/quit":raise QuitProgram()
            if line=="/exit":break
            if line=="/help":print(HELP);continue
            if line.startswith("/upload "):
                for p in paths(line[9:]):client_upload(sock,aes,lock,p)
            elif line=="/who":send_text(sock,aes,"__WHO__",lock)
            elif line in ("/typing on","/typing off"):
                send_text(sock,aes,"__TYPING__|"+line.rsplit(None,1)[1],lock)
            elif line.startswith("/kick "):send_text(sock,aes,"__MOD__|kick|"+line[6:].strip(),lock)
            elif line.startswith("/ban "):send_text(sock,aes,"__MOD__|ban|"+line[5:].strip(),lock)
            elif line.startswith("/unban "):send_text(sock,aes,"__MOD__|unban|"+line[7:].strip(),lock)
            elif line.startswith("/mute "):send_text(sock,aes,"__MOD__|mute|"+line[6:].strip(),lock)
            elif line.startswith("/unmute "):send_text(sock,aes,"__MOD__|unmute|"+line[8:].strip(),lock)
            elif line.startswith("/msg "):
                parts=line[5:].split(None,1)
                if len(parts)==2:send_text(sock,aes,"__MSG__|"+parts[0]+"|"+parts[1],lock)
                else:print("Usage: /msg <nickname> <message>")
            elif line=="/download":send_text(sock,aes,"__LIST__",lock)
            elif line.startswith("/download "):
                n,d=download_args(line[10:]);state["dir"]=d;client_config["download_dir"]=d;config_save(client_config);send_text(sock,aes,"__GET__|"+n,lock)
            elif line=="/history":send_text(sock,aes,"__HISTORY__",lock)
            else:send_text(sock,aes,line,lock)
    except (EOFError,OSError):pass
    finally:
        state["stop"].set()
        try:sock.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        sock.close()

def run_global():
    print("Global UDP mode is not authenticated; use a strong shared passphrase and do not use it for sensitive data.")
    password=input("Shared global passphrase: ").strip()
    if not password:
        print("[A passphrase is required]"); return
    salt=b"terminal-chat-global-v2"
    aes=AESGCM(key_from_password(password,salt)); nick=input("Nickname: ").strip() or "Guest"; own=secrets.token_hex(8)
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1); sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    try:sock.bind(("",GLOBAL_PORT))
    except OSError as e:print(f"[Could not bind global port: {e}]");sock.close();return
    def listen():
        while True:
            try:data,_=sock.recvfrom(FRAME_MAX); sender,msg=decrypt(aes,data).split("|",1)
            except (OSError,InvalidTag,ValueError,UnicodeError):return
            if sender!=own:print(f"\\r{msg}\\nYou: ",end="")
    threading.Thread(target=listen,daemon=True).start(); clear_terminal(); print("Global room started. Messages will remain visible until you leave.")
    try:
        while True:
            text=input("You: ")
            if text=="/quit":raise QuitProgram()
            if text=="/exit":return
            if text=="/help":print(HELP);continue
            sock.sendto(encrypt(aes,f"{own}|{nick}: {text}"),("<broadcast>",GLOBAL_PORT))
    except (EOFError,OSError):pass
    finally:sock.close()

def main():
    clear_terminal()
    while True:
        clear_terminal()
        try:choice=input("[s] host  [c] join  [g] global  [q] quit: ").strip().lower()
        except EOFError:return
        try:
            if choice=="s":run_server()
            elif choice=="c":run_client()
            elif choice=="g":run_global()
            elif choice in ("q","quit","/quit"):return
            else:print("Choose s, c, or q.")
        except QuitProgram:return
if __name__=="__main__":main()
