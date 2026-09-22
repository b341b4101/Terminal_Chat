# Terminal Chat

A small encrypted LAN terminal chat written in Python.

## Run

```bash
python -m pip install -r requirements.txt
python chat.py
```

Choose `s` to host or `c` to join. Automatic discovery uses UDP port `5001`; chat uses the configured TCP port (default `5000`). Firewall rules may need to allow Python on the local network.

## Configuration

`config.txt` controls the host:

- `port` and `max_members` are validated.
- `room_name` is shown during discovery.
- A non-empty `password` creates a private room.
- `nickname` avoids asking the host's nickname every time.
- `room_salt` is generated and persisted automatically. It is included in discovery so clients can derive the same key; manual connections need the salt shown in the host's config.

Leaving `password` empty creates an open room using the legacy public-room key. Open rooms are convenient, but they do not provide access control. Use a strong password for private communication.

## Files

Files and folders are transferred in encrypted 64 KiB chunks. Transfers show upload progress, include a SHA-256 checksum, and downloads are written to a `.part` file before being atomically renamed into place. The program does not load a complete file into RAM. The server stores encrypted chunks in a temporary directory and removes them when the room closes. Folder uploads are streamed from a temporary ZIP archive.

The protocol still limits individual control/data frames to 1 MiB, preventing a malformed peer from requesting an unbounded allocation.

## Security and limitations

Private room messages and file chunks use AES-256-GCM with a fresh nonce per message/chunk and PBKDF2-HMAC-SHA256 with 480,000 iterations and a per-room random salt. Incoming frames, nicknames, metadata, filenames, file sizes, and malformed cryptographic data are validated. Server writes use per-connection locks so concurrent broadcasts cannot corrupt TCP framing.

The open-room mode is intentionally public: its shared key is available to every participant. It should not be used for sensitive data. UDP discovery responses are treated only as a room directory; after selection, the TCP connection performs a fresh HMAC challenge-response using the room password before any nickname or chat data is accepted. This prevents a spoofed discovery response or wrong-password client from joining a room.

Hosts also enforce configurable per-file and total room-storage limits (`max_file_size_mb` and `max_room_storage_mb`, with defaults of 2048 MiB and 8192 MiB). Files exceeding either limit are rejected before the server stores them. `/who`, `/msg`, `/history`, timestamps, and heartbeat messages are supported in the TCP room.

This is still a local-network application, not a replacement for a mature audited messenger. There are no automated reconnects, certificate-based identity checks, or forward secrecy.
