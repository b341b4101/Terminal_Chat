# Terminal Chat: How It Works

This guide explains the application from the outside in. It is written for learning, so it describes both **what** a feature does and **why** it exists.

## 1. The big picture

Terminal Chat is a local-network client/server application:

- A **host** opens a TCP listening socket and owns a room.
- A **client** discovers or connects to the host and joins the room.
- UDP is used only for optional room discovery.
- TCP carries nicknames, chat messages, commands, and encrypted file data.
- The terminal loop reads user commands while a background receiver prints incoming events.

The main implementation is currently in `chat.py`. The tests are in `test_chat.py` and the host defaults are in `config.txt`.

## 2. Discovery versus connection

Discovery is a convenience, not authentication. A host listens on UDP port `5001` and answers a discovery request with its room name, TCP port, room kind, and salt. UDP can be spoofed or lost, so the client must not trust the response as proof of identity.

After choosing a discovered room, the client connects to TCP. The TCP handshake proves that both sides know the room password before the nickname or chat protocol begins. This separation is important: discovery helps find a room, while the authenticated TCP connection protects the room.

## 3. Framing TCP data

TCP is a continuous stream; it does not preserve message boundaries. The program adds a four-byte big-endian length before every frame:

```text
[length: 4 bytes][payload: length bytes]
```

`send_frame` writes one complete frame. `receive_exact` keeps reading until it has all requested bytes. Every frame is checked against `FRAME_MAX`, preventing a peer from asking the program to allocate an unbounded amount of memory.

A per-connection send lock is used because several threads can send messages to the same socket. Without the lock, two length prefixes could be interleaved and corrupt the stream.

## 4. Encryption and authentication

Room keys are derived from the password with PBKDF2-HMAC-SHA256 and a random per-room salt. AES-256-GCM then encrypts messages and file chunks. GCM provides confidentiality and authentication: changing ciphertext causes decryption to fail.

Before encrypted chat data, the server sends a fresh random challenge. The client returns an HMAC proof based on the password-derived key, and the server returns a second proof. Fresh challenges prevent replaying an old login exchange.

The open room remains intentionally open to anyone who knows its public-room key. Use a non-empty, strong password for private communication. A mature production messenger would additionally use verified certificates and a modern forward-secret key exchange.

## 5. Chat messages and commands

Normal text is encrypted and broadcast to the other participants. Control messages use reserved prefixes such as `__LIST__`, `__GET__|`, and `__UPLOAD__|`. Control messages are still inside the encrypted, length-bounded protocol, so they are not visible to passive network observers.

The host keeps a current-room file index and removes temporary room storage when the room closes. The current command set is shown by `/help` and includes:

- `/upload <path>` — upload a file or ZIP a folder and upload it.
- `/download` — list available files.
- `/download <number> [folder]` — download one file.
- `/download -a [folder]` — download all files.
- `/help` — show help.
- `/exit` — leave the room and return to the main menu.
- `/quit` — close the application.

## 6. File transfer

Files are read in 64 KiB pieces instead of loading an entire file into memory. Each piece gets its own random AES-GCM nonce. The server stores encrypted chunks in a temporary directory, so plaintext room files are not retained by the host.

A file announcement includes a name and declared size. The receiver counts decrypted bytes and rejects data that exceeds or fails to reach the declared size. Names are reduced to safe basenames and downloads receive a `received_` prefix with collision handling.

Hosts enforce both a per-file limit and a total room-storage limit. These are configured in MiB using `max_file_size_mb` and `max_room_storage_mb`.

## 7. Configuration

Important settings in `config.txt`:

- `port`: TCP port, normally between 1024 and 65535.
- `max_members`: maximum number of private-room clients.
- `room_name`: name shown during discovery.
- `password`: empty means public/open mode; non-empty enables private mode.
- `nickname`: saved host/client nickname.
- `room_salt`: generated automatically and needed for manual connections.
- `max_file_size_mb`: largest accepted file.
- `max_room_storage_mb`: total file storage allowed in one room.

Never publish a private room password or its configuration file in a public repository.

## 8. Concurrency model

The host has one accept loop and one handler thread per client. A separate discovery thread listens for UDP requests. The client has a receiver thread so incoming messages can appear while the user types.

Shared dictionaries are protected by locks:

- `room.lock` protects connected clients.
- `room.file_lock` protects the file index.
- Each socket has a send lock protecting TCP writes.

When adding a new shared structure, identify its owner and lock before adding a thread that accesses it.

## 9. Testing and extending

Run tests with the project's virtual environment:

```bash
.win-venv/Scripts/python.exe -m unittest -v
```

Useful extension rules:

1. Add a protocol constant instead of scattering a string literal.
2. Validate input at the boundary before using it.
3. Keep network reads bounded and cancellable.
4. Encrypt control data as well as ordinary text.
5. Add a unit test for each parser, validator, and cryptographic exchange.
6. Add an integration test using local sockets before changing both client and server.

The natural next architectural step is splitting `chat.py` into protocol, crypto, file transfer, room state, and terminal UI modules. Keeping those responsibilities separate makes security review and future graphical interfaces much easier.

## 10. Known security limits

This is an educational LAN application, not an audited messenger. UDP discovery is not itself authenticated. The current room key is password-derived and the current protocol does not provide certificate identity or full forward secrecy. It should not be used for high-value secrets until those properties are deliberately designed, implemented, and reviewed.
