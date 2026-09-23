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


if __name__ == "__main__":
    unittest.main()
