import os
import tempfile
import time
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import chat


class ChatHelpersTests(unittest.TestCase):
    def test_encrypted_chunk_round_trip(self):
        aes = AESGCM(os.urandom(32))
        payload = os.urandom(chat.CHUNK * 2 + 7)
        self.assertEqual(chat.dec_chunk(aes, chat.enc_chunk(aes, payload)), payload)

    def test_frame_rejects_oversized_payload(self):
        with self.assertRaises(ValueError):
            chat.send_frame(object(), b"x" * (chat.FRAME_MAX + 1))

    def test_safe_name_cannot_escape_destination(self):
        self.assertEqual(chat.safe_name("../../secret.txt"), "secret.txt")
        self.assertNotIn("|", chat.safe_name("a|b.txt"))

    def test_collision_free_name(self):
        with tempfile.TemporaryDirectory() as directory:
            open(os.path.join(directory, "received_a.txt"), "wb").close()
            result = chat.target("a.txt", directory)
            self.assertTrue(result.endswith("received_a_1.txt"))

    def test_config_has_random_salt_and_file_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.txt")
            config = chat.config_load(path)
            self.assertEqual(len(bytes.fromhex(config["room_salt"])), chat.SALT_SIZE)
            self.assertEqual(chat.config_load(path)["room_salt"], config["room_salt"])
            self.assertEqual(config["max_file_size_mb"], 2048)
            self.assertEqual(config["max_room_storage_mb"], 8192)

    def test_room_message_contains_sender_and_text(self):
        message = chat.room_message("Alice", "hello")
        self.assertIn("Alice: hello", message)
        self.assertTrue(message.startswith("["))

    def test_terminal_colors_are_escape_codes_not_literal_text(self):
        self.assertEqual(chat.ANSI["reset"], "\x1b[0m")
        self.assertNotIn("\\033", chat.ANSI["reset"])

    def test_client_message_colors_match_message_types(self):
        self.assertEqual(chat.message_kind("[2026-09-22 15:00:00] Alice: hello"), "message")
        self.assertEqual(chat.message_kind("[Alice joined the group]"), "system")
        self.assertEqual(chat.message_kind("[private Alice -> you] hi"), "private")

    def test_every_advertised_command_is_recognized(self):
        samples = {
            "/upload x": "upload",
            "/download": "download_list",
            "/download 1 ./d": "download",
            "/who": "who",
            "/msg Alice hi": "msg",
            "/history": "history",
            "/typing on": "typing",
            "/typing off": "typing",
            "/kick Alice": "kick",
            "/ban Alice": "ban",
            "/unban Alice": "unban",
            "/mute Alice": "mute",
            "/unmute Alice": "unmute",
            "/help": "help",
            "/exit": "exit",
            "/quit": "quit",
        }
        for line, expected in samples.items():
            self.assertEqual(chat.parse_command(line)[0], expected, line)

    def test_private_message_parsing_keeps_target_and_text(self):
        self.assertEqual(chat.parse_command("/msg Alice hello there")[1], ("Alice", "hello there"))
        self.assertEqual(chat.parse_command("/msg")[0], "usage")
        self.assertEqual(chat.parse_command("/typing maybe")[0], "usage")

    def test_normal_chat_line_is_not_a_command(self):
        self.assertEqual(chat.parse_command("hello /who")[0], "say")

    def test_upload_argument_keeps_leading_path_characters(self):
        self.assertEqual(chat.parse_command("/upload /tmp/a.txt")[1], "/tmp/a.txt")
        self.assertEqual(chat.parse_command("/upload C:/Users/me/My File.txt")[1], "C:/Users/me/My File.txt")
        self.assertEqual(chat.parse_command("/upload /a /b")[1], "/a /b")
        self.assertEqual(chat.parse_command("/upload \"C:/x y/one\" \"C:/z/two\"")[1], '"C:/x y/one" "C:/z/two"')

    def test_command_edges_report_usage_instead_of_chatting(self):
        for line in ("/typing", "/msg", "/kick", "/ban", "/unban", "/mute", "/unmute", "/upload"):
            self.assertEqual(chat.parse_command(line)[0], "usage", line)
        self.assertEqual(chat.parse_command("")[0], "empty")
        self.assertEqual(chat.parse_command("   ")[0], "empty")
        self.assertEqual(chat.parse_command("/download   ")[0], "download_list")
        self.assertEqual(chat.parse_command("/nope")[0], "unknown")

    def test_upload_header_size_parsing(self):
        self.assertEqual(chat.upload_header_size('__UPLOAD__|{"name":"a.bin","size":12}'), 12)
        self.assertIsNone(chat.upload_header_size('__UPLOAD__|{"name":"a.bin"}'))
        self.assertIsNone(chat.upload_header_size('__UPLOAD__|not json'))
        self.assertIsNone(chat.upload_header_size('__UPLOAD__|{"size":"12"}'))

    def test_client_receive_stops_quietly_after_shutdown(self):
        import contextlib
        import io
        import socket
        import threading

        left, right = socket.socketpair()
        state = {"dir": tempfile.gettempdir(), "stop": threading.Event()}
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            worker = threading.Thread(target=chat.client_receive, args=(left, AESGCM(os.urandom(32)), state), daemon=True)
            worker.start()
            time.sleep(0.2)
            state["stop"].set()
            try:
                left.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            left.close()
            right.close()
            worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertNotIn("[Connection closed", captured.getvalue())

    def test_client_receive_reports_a_real_server_side_close(self):
        import contextlib
        import io
        import socket
        import threading

        left, right = socket.socketpair()
        state = {"dir": tempfile.gettempdir(), "stop": threading.Event()}
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            worker = threading.Thread(target=chat.client_receive, args=(left, AESGCM(os.urandom(32)), state), daemon=True)
            worker.start()
            time.sleep(0.2)
            right.close()
            worker.join(timeout=2)
        left.close()
        self.assertTrue(state["stop"].is_set())
        self.assertIn("closed the connection", captured.getvalue())

    def test_authentication_challenge_round_trip(self):
        import socket
        key = os.urandom(32)
        left, right = socket.socketpair()
        try:
            import threading
            result = []
            thread = threading.Thread(target=lambda: result.append(chat.authenticate_server(left, key)))
            thread.start()
            chat.authenticate_client(right, key)
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
            self.assertEqual(result, [None])
        finally:
            left.close()
            right.close()


class ChatIntegrationTests(unittest.TestCase):
    """End-to-end check over a real socket that private messages and typing work."""

    def _serve(self, server, key, aes, room, captured):
        try:
            client, _ = server.accept()
            try:
                chat.authenticate_server(client, key)
                chat.handler(client, None, aes, room, 10, "Server")
            finally:
                client.close()
        except OSError:
            pass

    def test_private_message_and_typing_round_trip(self):
        import contextlib
        import io
        import socket
        import threading

        key = os.urandom(32)
        aes = AESGCM(key)
        room = chat.Room()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            thread = threading.Thread(target=self._serve, args=(server, key, aes, room, captured), daemon=True)
            thread.start()
            client = socket.create_connection(("127.0.0.1", port), 5)
            client.settimeout(5)
            try:
                chat.authenticate_client(client, key)
                chat.send_text(client, aes, "Bob")
                self.assertEqual(chat.decrypt(aes, chat.receive_frame(client)), "__NICK_OK__")
                chat.send_text(client, aes, "__MSG__|Server|hello host")
                self.assertEqual(chat.decrypt(aes, chat.receive_frame(client)), "[private you -> Server] hello host")
                chat.send_text(client, aes, "__TYPING__|on")
                time.sleep(0.2)
            finally:
                client.close()
            thread.join(timeout=3)
        output = captured.getvalue()
        self.assertIn("[private Bob -> you] hello host", output)
        self.assertIn("[typing] Bob is typing", output)
        room.close()
        server.close()

    def test_control_looking_chat_text_is_never_executed(self):
        """Chat text such as __WHO__ must be delivered as a normal message, not run as a command."""
        import contextlib
        import io
        import socket
        import threading

        key = os.urandom(32)
        aes = AESGCM(key)
        room = chat.Room()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(2)
        port = server.getsockname()[1]

        def serve_one(client):
            try:
                chat.authenticate_server(client, key)
                chat.handler(client, None, aes, room, 10, "Server")
            except OSError:
                pass

        def serve():
            try:
                while True:
                    client, _ = server.accept()
                    threading.Thread(target=serve_one, args=(client,), daemon=True).start()
            except OSError:
                pass

        with contextlib.redirect_stdout(io.StringIO()) as captured:
            threading.Thread(target=serve, daemon=True).start()
            bob = socket.create_connection(("127.0.0.1", port), 5)
            bob.settimeout(5)
            chat.authenticate_client(bob, key)
            chat.send_text(bob, aes, "Bob")
            self.assertEqual(chat.decrypt(aes, chat.receive_frame(bob)), "__NICK_OK__")
            ann = socket.create_connection(("127.0.0.1", port), 5)
            ann.settimeout(5)
            chat.authenticate_client(ann, key)
            chat.send_text(ann, aes, "Ann")
            self.assertEqual(chat.decrypt(aes, chat.receive_frame(ann)), "__NICK_OK__")
            self.assertIn("Ann joined the group", chat.decrypt(aes, chat.receive_frame(bob)))
            chat.send_text(bob, aes, "__SAY__|__WHO__")
            self.assertTrue(chat.decrypt(aes, chat.receive_frame(ann)).endswith("Bob: __WHO__"))
            time.sleep(0.2)
            bob.close()
            ann.close()
        self.assertIn("Bob: __WHO__", captured.getvalue())
        room.close()
        server.close()

    def test_rejected_upload_is_discarded_without_killing_the_session(self):
        """An upload over the room limit must be drained, reported, and the session kept alive."""
        import contextlib
        import io
        import json
        import socket
        import threading

        key = os.urandom(32)
        aes = AESGCM(key)
        room = chat.Room(max_file_size=10, max_storage=10)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            thread = threading.Thread(target=self._serve, args=(server, key, aes, room, captured), daemon=True)
            thread.start()
            client = socket.create_connection(("127.0.0.1", port), 5)
            client.settimeout(5)
            try:
                chat.authenticate_client(client, key)
                chat.send_text(client, aes, "Bob")
                self.assertEqual(chat.decrypt(aes, chat.receive_frame(client)), "__NICK_OK__")
                payload = b"x" * 64
                chat.send_text(client, aes, "__UPLOAD__|" + json.dumps({"name": "big.bin", "size": len(payload)}))
                chat.send_frame(client, chat.enc_chunk(aes, payload))
                reply = chat.decrypt(aes, chat.receive_frame(client))
                self.assertIn("Upload rejected", reply)
                chat.send_text(client, aes, "still here")
                time.sleep(0.2)
            finally:
                client.close()
            thread.join(timeout=3)
        self.assertIn("Bob: still here", captured.getvalue())
        room.close()
        server.close()


if __name__ == "__main__":
    unittest.main()
