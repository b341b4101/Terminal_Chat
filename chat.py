"""
Encrypted chat - everything in one file.

When started, main() asks which role you want to take:
  [s] Host a server   - you open a room (private with password, or global
                         with no password/limit), others connect to YOU.
                         Supports file sharing via /upload and /download.
  [c] Join as client  - you search for a running server on the network
                         (or type its IP manually) and join it.
  [g] Global peer chat - NO host needed: everyone is equal, messages go
                          directly to everyone on the same network via
                          UDP broadcast. No file sharing (UDP is not
                          suitable for that - see below).

All three modes share the same building blocks (encryption, framing,
discovery), which is why they are grouped together at the top.
"""

import socket
import threading
import os
import struct
import time
import sys
import ctypes
import zipfile
import io
import shlex

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# =========================================================================
# SHARED BUILDING BLOCKS (used by server, client AND the global chat)
# =========================================================================

DISCOVERY_PORT = 5001              # port on which servers listen for "who's there?" requests
DISCOVERY_REQUEST = b"CHAT_DISCOVER_V1"
DISCOVERY_REPLY_PREFIX = "CHAT_HERE_V1"

SALT = b"chat-room-fixed-salt-v1"          # fixed salt for PBKDF2 (see key_from_password)
GLOBAL_PASSWORD = "open-world-chat-fixed"  # hardcoded, used for "global"/hostless rooms

GLOBAL_CHAT_PORT = 52731  # dedicated port for the hostless peer-to-peer chat (role "g")
# Note: if this port gets blocked on your machine with WinError 10013
# (commonly caused by Windows' Hyper-V/WSL port reservations), just change
# it to another number between 1024 and 65535 - just make sure it's NOT
# inside a range shown by 'netsh interface ipv4 show excludedportrange
# protocol=udp'. It must be identical for everyone taking part!

# Markers used to recognise file-related commands inside the normal text
# message stream (only relevant in server/client mode, not the peer chat):
UPLOAD_MARKER = "__UPLOAD__"  # client is uploading a file to the server
LIST_REQUEST = "__LIST__"     # client is asking "which files are available?"
GET_MARKER = "__GET__"        # client is requesting a specific file (by number, or "-a" for all)
FILE_MARKER = "__FILE__"      # server is sending a requested file back
NICK_OK_MARKER = "__NICK_OK__"  # server confirms a nickname was accepted


class QuitProgram(Exception):
    """
    Raised when the user types /quit. It's allowed to propagate all the
    way up through client_send()/run_client() etc. back to main(), which
    catches it and ends the program. /exit, in contrast, just breaks out
    of the current input loop normally so the calling function returns
    to the start menu instead - no program-wide unwinding needed for that.
    """
    pass


def key_from_password(password: str, salt: bytes = SALT) -> bytes:
    """Derives a 32-byte AES-256 key from a password (PBKDF2, 480,000 rounds)."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480_000)
    return kdf.derive(password.encode())


def send_frame(conn: socket.socket, data: bytes) -> None:
    """Sends data prefixed with a 4-byte length field (TCP has no built-in message boundaries)."""
    length = struct.pack(">I", len(data))
    conn.sendall(length + data)


def receive_exact(conn: socket.socket, count: int):
    """Reads exactly 'count' bytes. Returns None if the connection ends early."""
    buffer = b""
    while len(buffer) < count:
        chunk = conn.recv(count - len(buffer))
        if not chunk:
            return None
        buffer += chunk
    return buffer


def receive_frame(conn: socket.socket):
    """Reads one complete message that was sent with send_frame()."""
    length_bytes = receive_exact(conn, 4)
    if length_bytes is None:
        return None
    (length,) = struct.unpack(">I", length_bytes)
    return receive_exact(conn, length)


def encrypt(aesgcm: AESGCM, text: str) -> bytes:
    """Encrypts text with AES-256-GCM (fresh nonce per message)."""
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, text.encode(), None)


def decrypt(aesgcm: AESGCM, data: bytes) -> str:
    """Reverses encrypt(). Raises InvalidTag if the key is wrong."""
    nonce, ciphertext = data[:12], data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode()


def encrypt_bytes(aesgcm: AESGCM, data: bytes) -> bytes:
    """Like encrypt(), but for raw binary data (e.g. file contents)."""
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, data, None)


def decrypt_bytes(aesgcm: AESGCM, data: bytes) -> bytes:
    """Reverses encrypt_bytes() - returns raw bytes, not text."""
    nonce, ciphertext = data[:12], data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


def explain_bind_error(error: OSError, port: int) -> None:
    """
    Prints a human-readable explanation when socket.bind() fails, instead
    of the program crashing with a cryptic traceback.

    Most common case on Windows: 'WinError 10013' (access denied). This
    does NOT necessarily mean anything is wrong with the code - typical
    causes are:
    - Windows Firewall is blocking Python for this port (often a prompt
      appears the very first time you run the program - if you dismissed
      or denied it, Windows keeps blocking the port since then).
    - Antivirus software is blocking the connection.
    - The port is reserved by Windows itself (common if Hyper-V or WSL
      is installed - they automatically reserve port ranges). Check with:
      netsh interface ipv4 show excludedportrange protocol=udp
    """
    print(f"\n[Error reserving port {port}: {error}]")
    print("Possible causes (especially on Windows):")
    print("  - Windows Firewall is blocking Python for this port")
    print("    -> Windows Security > Firewall > allow the app, or disable the firewall temporarily to test")
    print("  - Antivirus software is blocking the connection")
    print("  - The port is reserved by Windows (e.g. by Hyper-V/WSL) - check with:")
    print("      netsh interface ipv4 show excludedportrange protocol=udp")
    print("    Fix: use a different port (see GLOBAL_CHAT_PORT/DISCOVERY_PORT in the code).\n")


def notify_new_activity() -> None:
    """
    Alerts you (sound + flashing taskbar icon on Windows, terminal bell
    elsewhere) ONLY if this window is currently not focused - so you
    don't get spammed with alerts while you're actively looking at the chat.

    How the Windows focus check works: GetConsoleWindow() gives us the
    handle of THIS terminal window, GetForegroundWindow() gives the handle
    of whatever window the user currently has focused. If they differ,
    the chat window is in the background, so we flash it in the taskbar
    (FlashWindowEx) and play a short beep.

    Wrapped in try/except: notifications are a nice-to-have and should
    never be able to crash the chat, even on an unusual system.
    """
    try:
        if sys.platform.startswith("win"):
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            console_hwnd = kernel32.GetConsoleWindow()
            foreground_hwnd = user32.GetForegroundWindow()
            if console_hwnd and console_hwnd != foreground_hwnd:
                try:
                    import winsound
                    winsound.MessageBeep()
                except Exception:
                    pass

                class FLASHWINFO(ctypes.Structure):
                    _fields_ = [
                        ("cbSize", ctypes.c_uint),
                        ("hwnd", ctypes.c_void_p),
                        ("dwFlags", ctypes.c_uint),
                        ("uCount", ctypes.c_uint),
                        ("dwTimeout", ctypes.c_uint),
                    ]

                FLASHW_ALL = 0x00000003
                FLASHW_TIMERNOFG = 0x0000000C
                info = FLASHWINFO(ctypes.sizeof(FLASHWINFO), console_hwnd, FLASHW_ALL | FLASHW_TIMERNOFG, 5, 0)
                user32.FlashWindowEx(ctypes.byref(info))
        else:
            # No reliable cross-platform focus check without extra
            # dependencies - a terminal bell is a reasonable fallback,
            # most terminal emulators only actually alert you (flash the
            # taskbar icon, badge the dock icon, ...) when unfocused anyway.
            print("\a", end="", flush=True)
    except Exception:
        pass


def discovery_server(room_name: str, port: int, is_global: bool) -> None:
    """Background thread (server role) that answers "who's there?" broadcasts on the network."""
    search_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    search_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        search_socket.bind(("", DISCOVERY_PORT))
    except OSError as error:
        explain_bind_error(error, DISCOVERY_PORT)
        print("[Discovery disabled - others can't auto-find this server, manual IP entry still works]")
        return
    type_text = "global" if is_global else "private"
    while True:
        try:
            data, sender = search_socket.recvfrom(1024)
        except OSError:
            break
        if data == DISCOVERY_REQUEST:
            reply = f"{DISCOVERY_REPLY_PREFIX}|{room_name}|{port}|{type_text}".encode()
            search_socket.sendto(reply, sender)


def search_servers(timeout: float = 2.0):
    """(Client role) ONE search round via UDP broadcast. Returns a list of (ip, room_name, port, type)."""
    search_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    search_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    search_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    search_socket.sendto(DISCOVERY_REQUEST, ("<broadcast>", DISCOVERY_PORT))

    found_servers = []
    start_time = time.time()
    while True:
        remaining_time = timeout - (time.time() - start_time)
        if remaining_time <= 0:
            break
        search_socket.settimeout(remaining_time)
        try:
            data, sender = search_socket.recvfrom(1024)
        except socket.timeout:
            break
        text = data.decode(errors="ignore")
        if text.startswith(DISCOVERY_REPLY_PREFIX):
            parts = text.split("|")
            if len(parts) == 4:
                _, room_name, port_text, type_ = parts
                entry = (sender[0], room_name, port_text, type_)
                if entry not in found_servers:
                    found_servers.append(entry)
    search_socket.close()
    return found_servers


def search_servers_forever():
    """(Client role) Keeps searching FOREVER until at least one server is found (Ctrl+C = cancel)."""
    print("Searching for servers on the network... (Ctrl+C for manual IP entry)")
    try:
        while True:
            found = search_servers(timeout=2.0)
            if found:
                return found
    except KeyboardInterrupt:
        print()
        return []


def collision_free_filename(filename: str, destination_dir: str = ".") -> str:
    """
    Builds a target path '<destination_dir>/received_<name>' that doesn't
    exist yet (numbered on collision: _1, _2, ...). Used by both the
    server (its own /download command) and the client whenever a
    downloaded file is saved locally. destination_dir defaults to the
    current directory but can be any folder (see /download's optional
    destination argument) - it is created automatically if it doesn't
    exist yet.
    """
    try:
        os.makedirs(destination_dir, exist_ok=True)
    except OSError:
        destination_dir = "."  # couldn't create it (e.g. invalid path/permissions) - fall back safely
    target_path = os.path.join(destination_dir, f"received_{filename}")
    base, extension = os.path.splitext(target_path)
    counter = 1
    while os.path.exists(target_path):
        target_path = f"{base}_{counter}{extension}"
        counter += 1
    return target_path


HELP_TEXT = """Available commands:
  /upload <path>                  - upload a file or folder (folders are zipped automatically)
  /upload <path1>; <path2>        - upload several files/folders (separate with ';')
  /upload "path1" "path2" ...     - also works with space-separated quoted paths
                                     (this is what you get when you drag multiple
                                     files into the terminal window)
  /download                       - list files currently available for download
  /download <n>                   - download file number n (saved in the current folder)
  /download <n> <destination>     - download file number n into a specific folder
  /download -a                    - download all available files (current folder)
  /download -a <destination>      - download all available files into a specific folder
  /help                           - show this help text
  /exit                           - leave this chat and return to the start menu
  /quit                           - leave the chat and close the program entirely
Anything else you type is sent as a normal chat message."""


def clean_path(raw_path: str) -> str:
    """
    Cleans up a path the way it commonly arrives when pasted from a
    terminal or file explorer, so uploads don't fail on things you didn't
    type yourself:
    - PowerShell prefixes paths with '& ' when you use "Copy as path" and
      the path contains spaces (it's PowerShell's "call operator") - we
      strip that off if present.
    - Both PowerShell and Windows Explorer often wrap such paths in
      matching single or double quotes - we strip those too.
    - Leading/trailing whitespace is removed.
    """
    path = raw_path.strip()
    if path.startswith("&"):
        path = path[1:].strip()
    if len(path) >= 2 and path[0] == path[-1] and path[0] in ("'", '"'):
        path = path[1:-1]
    return path.strip()


def split_multiple_paths(raw_input: str) -> list:
    """
    Splits the argument of /upload into individual paths, supporting
    four input styles:

    1. Drag-and-drop WITH quotes: dragging files whose names contain
       spaces makes the terminal wrap each path in double quotes, e.g.
       '"C:\\a b.png" "C:\\c.png"'. Detected by the presence of quote
       characters; shlex splits on whitespace while respecting the quotes.
    2. Drag-and-drop WITHOUT quotes: if none of the filenames contain
       spaces, terminals often just insert the paths separated by plain
       spaces with no quoting at all, e.g. 'C:\\1.png C:\\2.png C:\\3.png'.
       This looks identical to "one path with spaces in it" from the
       program's point of view, so we resolve the ambiguity by checking
       the filesystem: if splitting on whitespace gives us MULTIPLE
       tokens and EVERY one of them actually exists, we treat them as
       separate paths. Otherwise we assume it's one path that happens to
       contain a space and leave it untouched.
    3. Manually typed multiple paths without quotes, separated by ';'
       (useful when a single path has spaces but you don't want to quote it).
    4. A single plain path (possibly containing spaces) - the whole
       remaining input is treated as one path.

    Each resulting path is cleaned with clean_path() (strips quotes/'&').
    """
    raw_input = raw_input.strip()
    if not raw_input:
        return []

    if '"' in raw_input or "'" in raw_input:
        # posix=False keeps backslashes literal (important for Windows
        # paths like C:\Users\...), whitespace_split=True makes it split
        # only on whitespace while still treating quotes as grouping.
        lexer = shlex.shlex(raw_input, posix=False)
        lexer.whitespace_split = True
        try:
            tokens = list(lexer)
        except ValueError:
            # Unbalanced quotes - safest fallback is to treat it as one path
            return [clean_path(raw_input)]
        return [clean_path(token) for token in tokens if clean_path(token)]

    if ";" in raw_input:
        return [clean_path(token) for token in raw_input.split(";") if clean_path(token)]

    space_separated = [clean_path(token) for token in raw_input.split() if clean_path(token)]
    if len(space_separated) > 1 and all(os.path.exists(token) for token in space_separated):
        return space_separated

    return [clean_path(raw_input)]


def parse_download_args(raw_input: str):
    """
    Parses the argument of '/download <n or -a> [destination]' into
    (number_or_all, destination). The destination is optional; if given
    it may be quoted (useful if the folder name has spaces).

    Examples:
        "1"                 -> ("1", ".")
        "1 C:\\Downloads"    -> ("1", "C:\\Downloads")
        '-a "My Downloads"' -> ("-a", "My Downloads")
    """
    raw_input = raw_input.strip()
    if '"' in raw_input or "'" in raw_input:
        lexer = shlex.shlex(raw_input, posix=False)
        lexer.whitespace_split = True
        try:
            tokens = [clean_path(t) for t in lexer]
        except ValueError:
            tokens = raw_input.split(None, 1)
    else:
        tokens = raw_input.split(None, 1)

    if not tokens:
        return "", "."
    number_or_all = tokens[0]
    destination = clean_path(tokens[1]) if len(tokens) > 1 else "."
    return number_or_all, destination


def zip_folder_to_bytes(folder_path: str) -> bytes:
    """
    Compresses an entire folder (including subfolders) into a .zip
    archive, entirely in memory (io.BytesIO) - no temporary file is
    written to disk. This is how folder uploads work: since our transfer
    protocol only knows how to send one blob of bytes with a name and a
    size, a folder gets turned into a single zip file first, and the
    receiving side ends up with a normal .zip they can extract themselves.
    """
    buffer = io.BytesIO()
    base_folder_name = os.path.basename(os.path.normpath(folder_path))
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for current_dir, _subdirs, filenames in os.walk(folder_path):
            for filename in filenames:
                full_path = os.path.join(current_dir, filename)
                # Path INSIDE the zip: keep the folder name itself as the
                # top-level entry, e.g. "myfolder/subdir/file.txt", so the
                # receiver gets a self-contained folder when they extract it.
                relative_path = os.path.join(
                    base_folder_name, os.path.relpath(full_path, folder_path)
                )
                zip_file.write(full_path, relative_path)
    return buffer.getvalue()


def read_upload_data(path: str):
    """
    Reads whatever is at 'path' so it can be uploaded: a regular file is
    read as-is, a folder is zipped first (see zip_folder_to_bytes()).

    Returns (filename, data) on success, or None if the path doesn't
    exist (the caller prints the "not found" message, since the exact
    wording differs slightly between the server's and the client's version).
    """
    if os.path.isdir(path):
        data = zip_folder_to_bytes(path)
        filename = os.path.basename(os.path.normpath(path)) + ".zip"
        return filename, data
    if os.path.isfile(path):
        with open(path, "rb") as f:
            data = f.read()
        return os.path.basename(path), data
    return None


# =========================================================================
# ROLE: SERVER (host a room)
# =========================================================================

CONFIG_FILE = "config.txt"
DEFAULT_CONFIG = {
    "port": "5000",
    "max_members": "10",
    "room_name": "Chat-Room",
    "password": "",   # leave empty for an open/global room (no password, no member limit)
    "nickname": "",   # leave empty to be asked for a nickname every time
}


def load_config(path: str = CONFIG_FILE) -> dict:
    """Reads server settings from a text file, creates it with defaults if it doesn't exist."""
    config = DEFAULT_CONFIG.copy()
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as file:
            for key, value in DEFAULT_CONFIG.items():
                file.write(f"{key}={value}\n")
        print(f"'{path}' was created with default values. Feel free to edit it.")
    else:
        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                config[key.strip()] = value.strip()
    config["port"] = int(config["port"])
    config["max_members"] = int(config["max_members"])
    return config


# clients: socket -> nickname. clients_lock protects against concurrent
# access from multiple handler threads (one per connected client).
clients: dict = {}
clients_lock = threading.Lock()

# files: number (int) -> {"name", "size", "from", "frame"} - uploaded files
# are kept here until someone fetches them with /download <n>.
files: dict = {}
next_file_number = 1
files_lock = threading.Lock()


def broadcast(aesgcm: AESGCM, text: str, sender_conn=None) -> None:
    """Encrypts 'text' and sends it to every client except 'sender_conn'."""
    with clients_lock:
        recipients = [conn for conn in clients if conn is not sender_conn]
    encrypted = encrypt(aesgcm, text)
    for conn in recipients:
        try:
            send_frame(conn, encrypted)
        except OSError:
            pass


def file_list_text() -> str:
    """Builds the text reply for the /download command (without a number)."""
    with files_lock:
        if not files:
            return "SERVER: No files available for download."
        lines = [
            f"[{number}] - {info['name']} ({info['size']} bytes, from {info['from']})"
            for number, info in sorted(files.items())
        ]
    return "SERVER: Available files:\n" + "\n".join(lines)


def client_handler(conn: socket.socket, addr, aesgcm: AESGCM, max_members, host_nickname: str) -> None:
    """
    One dedicated thread per connected client. Receives the nickname, then
    loops handling text messages or file commands (upload/list/get).
    """
    try:
        data = receive_frame(conn)
        if data is None:
            conn.close()
            return
        nickname = decrypt(aesgcm, data)
    except (InvalidTag, OSError):
        conn.close()
        return

    with clients_lock:
        group_full = max_members is not None and len(clients) >= max_members
        nickname_taken = (not group_full) and (
            nickname == host_nickname or nickname in clients.values()
        )
        if not group_full and not nickname_taken:
            clients[conn] = nickname

    if group_full:
        try:
            send_frame(conn, encrypt(aesgcm, "SERVER: Group is already full."))
        except OSError:
            pass
        conn.close()
        return

    if nickname_taken:
        try:
            send_frame(
                conn,
                encrypt(aesgcm, f"SERVER: Nickname '{nickname}' is already taken. Please reconnect with a different nickname."),
            )
        except OSError:
            pass
        conn.close()
        return

    try:
        send_frame(conn, encrypt(aesgcm, NICK_OK_MARKER))
    except OSError:
        conn.close()
        return

    print(f"\n[{nickname} joined - {addr[0]}]\nYou: ", end="")
    notify_new_activity()
    # Excludes the newly joined client itself (sender_conn=conn) - otherwise
    # they would receive their own "joined" notice right as their own
    # input prompt is showing, causing a duplicated "You: You:" on screen.
    broadcast(aesgcm, f"[{nickname} joined the group]", sender_conn=conn)

    while True:
        try:
            data = receive_frame(conn)
            if data is None:
                break
            text = decrypt(aesgcm, data)
        except InvalidTag:
            break
        except OSError:
            break

        if text == LIST_REQUEST:
            try:
                send_frame(conn, encrypt(aesgcm, file_list_text()))
            except OSError:
                break
            continue

        if text.startswith(GET_MARKER + "|"):
            _, number_text = text.split("|", 1)

            if number_text == "-a":
                with files_lock:
                    entries = list(sorted(files.items()))
                try:
                    if not entries:
                        send_frame(conn, encrypt(aesgcm, "SERVER: No files available for download."))
                    else:
                        for number, entry in entries:
                            header = f"{FILE_MARKER}|{entry['from']}|{entry['name']}|{entry['size']}"
                            send_frame(conn, encrypt(aesgcm, header))
                            send_frame(conn, entry["frame"])
                except OSError:
                    break
                continue

            with files_lock:
                entry = files.get(int(number_text)) if number_text.isdigit() else None
            try:
                if entry is None:
                    send_frame(conn, encrypt(aesgcm, "SERVER: Invalid file number."))
                else:
                    header = f"{FILE_MARKER}|{entry['from']}|{entry['name']}|{entry['size']}"
                    send_frame(conn, encrypt(aesgcm, header))
                    send_frame(conn, entry["frame"])
            except OSError:
                break
            continue

        if text.startswith(UPLOAD_MARKER + "|"):
            _, sender_nickname, filename, size_text = text.split("|", 3)
            file_frame = receive_frame(conn)  # the second frame is always the file itself
            if file_frame is None:
                break

            global next_file_number
            with files_lock:
                number = next_file_number
                next_file_number += 1
                files[number] = {
                    "name": filename,
                    "size": int(size_text),
                    "from": sender_nickname,
                    "frame": file_frame,  # stays encrypted - the server never sees the content
                }

            print(f"\r[{sender_nickname} uploaded '{filename}' -> number {number}]\nYou: ", end="")
            notify_new_activity()
            try:
                send_frame(conn, encrypt(aesgcm, f"SERVER: File uploaded as number {number}."))
            except OSError:
                break
            broadcast(aesgcm, f"[New file available: {filename} - see /download]", sender_conn=conn)
            continue

        print(f"\r{nickname}: {text}\nYou: ", end="")
        notify_new_activity()
        broadcast(aesgcm, f"{nickname}: {text}", sender_conn=conn)

    with clients_lock:
        clients.pop(conn, None)
    print(f"\n[{nickname} left the group]\nYou: ", end="")
    notify_new_activity()
    broadcast(aesgcm, f"[{nickname} left the group]")
    conn.close()


def accept_loop(server_sock: socket.socket, aesgcm: AESGCM, max_members, host_nickname: str) -> None:
    """Continuously accepts new connections, spawning one thread per client."""
    while True:
        try:
            conn, addr = server_sock.accept()
        except OSError:
            break
        threading.Thread(
            target=client_handler, args=(conn, addr, aesgcm, max_members, host_nickname), daemon=True
        ).start()


def server_upload_file(aesgcm: AESGCM, nickname: str, filepath: str) -> None:
    """Server uploads a file OR folder (via its own keyboard input) directly into storage - no network round-trip needed."""
    result = read_upload_data(filepath)
    if result is None:
        print(f"[Not found: {filepath}]")
        return
    filename, file_data = result

    global next_file_number
    with files_lock:
        number = next_file_number
        next_file_number += 1
        files[number] = {
            "name": filename,
            "size": len(file_data),
            "from": nickname,
            "frame": encrypt_bytes(aesgcm, file_data),
        }
    print(f"[File '{filename}' ({len(file_data)} bytes) uploaded as number {number}]")
    broadcast(aesgcm, f"[New file available: {filename} - see /download]")


def server_download_file(aesgcm: AESGCM, number_text: str, destination: str = ".") -> None:
    """Server downloads (via its own keyboard input) a stored file and saves it locally."""
    if number_text == "-a":
        with files_lock:
            entries = list(sorted(files.items()))
        if not entries:
            print("[No files available for download]")
            return
        for _, entry in entries:
            try:
                file_data = decrypt_bytes(aesgcm, entry["frame"])
            except InvalidTag:
                print(f"[Could not decrypt '{entry['name']}']")
                continue
            target_path = collision_free_filename(entry["name"], destination)
            with open(target_path, "wb") as f:
                f.write(file_data)
            print(f"[Saved as '{target_path}']")
        return

    with files_lock:
        entry = files.get(int(number_text)) if number_text.isdigit() else None
    if entry is None:
        print("[Invalid file number]")
        return
    try:
        file_data = decrypt_bytes(aesgcm, entry["frame"])
    except InvalidTag:
        print("[Could not decrypt file]")
        return
    target_path = collision_free_filename(entry["name"], destination)
    with open(target_path, "wb") as f:
        f.write(file_data)
    print(f"[Saved as '{target_path}']")


def run_server() -> None:
    """
    Entry point for the 'server' role (host a room).

    There's no separate "room type" question anymore - it's derived from
    the password: set one (interactively or in config.txt) and you get a
    private room; leave it empty and the room automatically becomes an
    open/global one (no password, no member limit) that anyone can join.
    """
    config = load_config()

    password = config["password"] or input("Set room password (leave empty for an open/global room): ").strip()
    is_global = not password

    if is_global:
        password = GLOBAL_PASSWORD
        max_members = None
    else:
        max_members = config["max_members"]
    room_name = config["room_name"]

    key = key_from_password(password)
    aesgcm = AESGCM(key)
    server_nickname = config["nickname"] or input("Your nickname: ").strip() or "Server"

    threading.Thread(
        target=discovery_server, args=(room_name, config["port"], is_global), daemon=True
    ).start()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind(("0.0.0.0", config["port"]))
    except OSError as error:
        explain_bind_error(error, config["port"])
        return
    server_sock.listen(5)
    limit_text = "unlimited" if max_members is None else str(max_members)
    kind_text = "open/global" if is_global else "private"
    print(f"\n'{room_name}' is running on port {config['port']} ({kind_text}, members: {limit_text}). Waiting...")
    print("Type /help to see all available commands.\n")

    threading.Thread(
        target=accept_loop, args=(server_sock, aesgcm, max_members, server_nickname), daemon=True
    ).start()

    try:
        while True:
            try:
                line = input("You: ")
            except EOFError:
                break
            if line == "/quit":
                raise QuitProgram()
            if line == "/exit":
                break
            if line == "/help":
                print(HELP_TEXT)
                continue
            if line.startswith("/upload "):
                for path in split_multiple_paths(line[len("/upload "):]):
                    server_upload_file(aesgcm, server_nickname, path)
                continue
            if line == "/download":
                print(file_list_text())
                continue
            if line.startswith("/download "):
                number_or_all, destination = parse_download_args(line[len("/download "):])
                server_download_file(aesgcm, number_or_all, destination)
                continue
            broadcast(aesgcm, f"{server_nickname}: {line}")
    finally:
        # Runs on /exit, /quit AND normal Ctrl+C/EOFError alike, so the
        # port is always freed - whether we're returning to the menu or
        # the whole program is about to end.
        server_sock.close()


# =========================================================================
# ROLE: CLIENT (join a server)
# =========================================================================

def client_receive(conn: socket.socket, aesgcm: AESGCM, download_state: dict) -> None:
    """
    (Client role) Background thread: displays messages, auto-downloads
    file replies (FILE_MARKER). 'download_state' is a small dict shared
    with client_send() - {"destination": "."} by default, or whatever
    folder the most recent /download command specified - so this thread
    knows where to save incoming files without the two functions needing
    a more complicated communication channel between them.
    """
    while True:
        try:
            data = receive_frame(conn)
            if data is None:
                print("\n[Connection closed]")
                break
            message = decrypt(aesgcm, data)
        except InvalidTag:
            print("\n[Could not decrypt message - wrong password?]")
            break
        except (ConnectionResetError, OSError):
            print("\n[Connection lost]")
            break

        if message.startswith(FILE_MARKER + "|"):
            _, sender_nickname, filename, size_text = message.split("|", 3)
            print(f"\r[{sender_nickname} is sending '{filename}' ({size_text} bytes) - downloading...]")

            file_frame = receive_frame(conn)  # second frame is always the file itself, always follows immediately
            if file_frame is None:
                print("[File transfer interrupted - connection closed]")
                break
            try:
                file_data = decrypt_bytes(aesgcm, file_frame)
            except InvalidTag:
                print("[Could not decrypt file]")
                continue

            target_path = collision_free_filename(filename, download_state["destination"])
            with open(target_path, "wb") as f:
                f.write(file_data)
            print(f"[Saved as '{target_path}']\nYou: ", end="")
            notify_new_activity()
            continue

        print(f"\r{message}\nYou: ", end="")
        notify_new_activity()


def client_upload_file(conn: socket.socket, aesgcm: AESGCM, nickname: str, filepath: str) -> None:
    """(Client role) Uploads a local file OR folder to the server (server does NOT push it to others automatically)."""
    result = read_upload_data(filepath)
    if result is None:
        print(f"[Not found: {filepath}]")
        return
    filename, file_data = result

    announcement = f"{UPLOAD_MARKER}|{nickname}|{filename}|{len(file_data)}"
    send_frame(conn, encrypt(aesgcm, announcement))
    send_frame(conn, encrypt_bytes(aesgcm, file_data))
    print(f"[Uploading '{filename}' ({len(file_data)} bytes)...]")


def client_send(conn: socket.socket, aesgcm: AESGCM, nickname: str, download_state: dict) -> None:
    """(Client role) Reads input and sends it - including /upload, /download, /help commands."""
    while True:
        try:
            line = input("You: ")
        except EOFError:
            break
        if line == "/quit":
            raise QuitProgram()
        if line == "/exit":
            break
        if line == "/help":
            print(HELP_TEXT)
            continue
        if line.startswith("/upload "):
            for path in split_multiple_paths(line[len("/upload "):]):
                client_upload_file(conn, aesgcm, nickname, path)
            continue
        if line == "/download":
            try:
                send_frame(conn, encrypt(aesgcm, LIST_REQUEST))
            except OSError:
                break
            continue
        if line.startswith("/download "):
            number_or_all, destination = parse_download_args(line[len("/download "):])
            # Tell the background thread where to save the file(s) that
            # are about to arrive as a response to this specific request.
            download_state["destination"] = destination
            try:
                send_frame(conn, encrypt(aesgcm, f"{GET_MARKER}|{number_or_all}"))
            except OSError:
                break
            continue
        try:
            send_frame(conn, encrypt(aesgcm, line))
        except OSError:
            break


def run_client() -> None:
    """Entry point for the 'client' role (join a server)."""
    found_servers = search_servers_forever()

    if found_servers:
        print("\nFound servers:")
        for number, (ip, room_name, port_text, type_) in enumerate(found_servers, start=1):
            type_display = "public" if type_ == "global" else "private, password required"
            print(f"  {number}) {room_name}  ({ip}) - {type_display}")
        choice = input("\nEnter a number, or press Enter for manual IP entry: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(found_servers):
            target_ip, _, port_text, type_ = found_servers[int(choice) - 1]
            target_port = int(port_text)
            is_global = type_ == "global"
        else:
            target_ip = input("Server IP address: ").strip() or "127.0.0.1"
            target_port = 5000
            is_global = False
    else:
        target_ip = input("Server IP address: ").strip() or "127.0.0.1"
        target_port = 5000
        is_global = False

    if is_global:
        password = GLOBAL_PASSWORD
    else:
        password = input("Room password (leave empty = global chat, if connecting by IP): ").strip()
        if not password:
            password = GLOBAL_PASSWORD

    key = key_from_password(password)
    aesgcm = AESGCM(key)

    # Nicknames must be unique within a room - if the server rejects ours
    # (already taken), it tells us why and closes the connection, so we
    # just open a fresh one and try again with a different nickname.
    client = None
    nickname = None
    while client is None:
        nickname = input("Your nickname: ").strip() or "Guest"
        candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        candidate.connect((target_ip, target_port))
        send_frame(candidate, encrypt(aesgcm, nickname))
        reply_data = receive_frame(candidate)
        if reply_data is None:
            print("[Connection closed unexpectedly]")
            candidate.close()
            return
        reply = decrypt(aesgcm, reply_data)
        if reply == NICK_OK_MARKER:
            client = candidate
        else:
            print(reply)  # e.g. "SERVER: Nickname 'X' is already taken. ..."
            candidate.close()

    print(f"\nConnected to {target_ip}:{target_port} as '{nickname}'.")
    print("Type /help to see all available commands.\n")

    # Shared between the two threads below - see client_receive()'s docstring.
    download_state = {"destination": "."}

    threading.Thread(target=client_receive, args=(client, aesgcm, download_state), daemon=True).start()
    try:
        client_send(client, aesgcm, nickname, download_state)
    finally:
        # Runs on /exit, /quit AND normal Ctrl+C/EOFError alike.
        client.close()


# =========================================================================
# ROLE: GLOBAL PEER CHAT (no host, UDP broadcast, no file sharing)
# =========================================================================

def global_listen(sock: socket.socket, aesgcm: AESGCM, own_id: str) -> None:
    """
    (Peer role) Background thread. Since we send via broadcast AND listen
    on the same port, we also receive our own messages back - 'own_id'
    filters those out (see run_global_chat()).
    """
    while True:
        try:
            data, sender = sock.recvfrom(4096)
        except OSError:
            break
        try:
            plaintext = decrypt(aesgcm, data)
        except InvalidTag:
            continue
        sender_id, _, message = plaintext.partition("|")
        if sender_id == own_id:
            continue  # our own message that we just sent - don't show it twice
        print(f"\r{message}\nYou: ", end="")
        notify_new_activity()


def global_send(sock: socket.socket, aesgcm: AESGCM, own_id: str, nickname: str) -> None:
    """(Peer role) Reads input and broadcasts it to everyone on the network."""
    while True:
        try:
            text = input("You: ")
        except EOFError:
            break
        if text == "/quit":
            raise QuitProgram()
        if text == "/exit":
            break
        if text == "/help":
            print("This is the hostless global chat - just type to broadcast a message. No file sharing here.\n/exit - back to menu, /quit - close the program")
            continue
        message = f"{own_id}|{nickname}: {text}"
        try:
            sock.sendto(encrypt(aesgcm, message), ("<broadcast>", GLOBAL_CHAT_PORT))
        except OSError:
            break


def run_global_chat() -> None:
    """Entry point for the 'global peer chat' role (no host needed)."""
    nickname = input("Your nickname: ").strip() or "Guest"
    own_id = os.urandom(4).hex()  # unique per program run, see global_listen()

    key = key_from_password(GLOBAL_PASSWORD)
    aesgcm = AESGCM(key)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind(("", GLOBAL_CHAT_PORT))
    except OSError as error:
        explain_bind_error(error, GLOBAL_CHAT_PORT)
        return

    threading.Thread(target=global_listen, args=(sock, aesgcm, own_id), daemon=True).start()

    print(f"\nJoined the global chat as '{nickname}'. Type /help for commands.\n")
    announcement = f"{own_id}|[{nickname} joined the global chat]"
    sock.sendto(encrypt(aesgcm, announcement), ("<broadcast>", GLOBAL_CHAT_PORT))

    try:
        global_send(sock, aesgcm, own_id, nickname)
    finally:
        sock.close()


# =========================================================================
# START MENU
# =========================================================================

def main() -> None:
    while True:
        print("What would you like to do?")
        print("  [s] Host a server     - open a room (private, or open/global if no password), including file sharing")
        print("  [c] Join as a client  - join a server that's already running")
        print("  [g] Global peer chat  - no host, talk directly with everyone on the network (no file sharing)")
        choice = input("Choice: ").strip().lower()

        try:
            if choice == "s":
                run_server()
            elif choice == "c":
                run_client()
            elif choice == "g":
                run_global_chat()
            else:
                print("Invalid choice - please enter 's', 'c' or 'g'.")
        except QuitProgram:
            print("Goodbye!")
            return
        print()  # blank line before the menu repeats, for readability


if __name__ == "__main__":
    main()