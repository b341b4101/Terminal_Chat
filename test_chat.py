import os
import tempfile
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

    def test_config_has_random_salt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.txt")
            config = chat.config_load(path)
            self.assertEqual(len(bytes.fromhex(config["room_salt"])), chat.SALT_SIZE)
            self.assertEqual(chat.config_load(path)["room_salt"], config["room_salt"])


if __name__ == "__main__":
    unittest.main()
