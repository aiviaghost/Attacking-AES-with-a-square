from functools import reduce
from secrets import token_bytes
import unittest

from aes import AES
from attack import recover_round_key, reverse_key_expansion, setup, check_key_guess, reverse_state
from util import xor


class Test_AES(unittest.TestCase):

    def test_rot_word(self):
        inp = bytes([0, 1, 2, 3])
        expected = bytes([1, 2, 3, 0])
        self.assertEqual(AES.rot_word(inp), expected)

    def test_sub_word(self):
        inp = bytes([0x01, 0xc2, 0x9e, 0xff])
        expected = bytes([0x7c, 0x25, 0x0b, 0x16])
        self.assertEqual(AES.sub_word(inp), expected)

    def test_rcon(self):
        rcon = [
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
            0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
            0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
            0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
            0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
            0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
        ]
        for i in range(256):
            expected = bytes((rcon[i], 0, 0, 0))
            self.assertEqual(AES.rcon(i), expected)

    def test_sbox(self):
        self.assertTrue(
            all(AES.INV_SBOX[AES.SBOX[i]] == i for i in range(256)))

    def test_key_expansion(self):
        original_key = "2b7e151628aed2a6abf7158809cf4f3c"
        expected = [
            "2b7e151628aed2a6abf7158809cf4f3c",
            "a0fafe1788542cb123a339392a6c7605",
            "f2c295f27a96b9435935807a7359f67f",
            "3d80477d4716fe3e1e237e446d7a883b",
            "ef44a541a8525b7fb671253bdb0bad00",
            "d4d1c6f87c839d87caf2b8bc11f915bc",
            "6d88a37a110b3efddbf98641ca0093fd",
            "4e54f70e5f5fc9f384a64fb24ea6dc4f",
            "ead27321b58dbad2312bf5607f8d292f",
            "ac7766f319fadc2128d12941575c006e",
            "d014f9a8c9ee2589e13f0cc8b6630ca6"
        ]
        self.assertEqual(AES.key_expansion(original_key)[
                         : AES.ROUNDS + 1], expected[: AES.ROUNDS + 1])

    def test_sub_bytes(self):
        inp = "000102030405060708090a0b0c0d0e0f"
        expcected = "637c777bf26b6fc53001672bfed7ab76"
        self.assertEqual(AES.sub_bytes(inp), expcected)

    def test_shift_rows(self):
        inp = "637c777bf26b6fc53001672bfed7ab76"
        expected = "636b6776f201ab7b30d777c5fe7c6f2b"
        self.assertEqual(AES.shift_rows(inp), expected)

    def test_mix_columns(self):
        inp = "636b6776f201ab7b30d777c5fe7c6f2b"
        expected = "6a6a5c452c6d3351b0d95d61279c215c"
        self.assertEqual(AES.mix_columns(inp), expected)

    def test_inverse_mix_columns(self):
        inp = "6a6a5c452c6d3351b0d95d61279c215c"
        expected = "636b6776f201ab7b30d777c5fe7c6f2b"
        self.assertEqual(AES.inverse_mix_columns(inp), expected)

    def test_add_round_key(self):
        state = "6a6a5c452c6d3351b0d95d61279c215c"
        round_key = "d6aa74fdd2af72fadaa678f1d6ab76fe"
        expected = "bcc028b8fec241ab6a7f2590f13757a2"
        self.assertEqual(AES.add_round_key(state, round_key), expected)

    def test_full_round(self):
        initial_state = "000102030405060708090a0b0c0d0e0f"
        round_key = "d6aa74fdd2af72fadaa678f1d6ab76fe"
        expected = "bcc028b8fec241ab6a7f2590f13757a2"
        res = AES.add_round_key(AES.mix_columns(AES.shift_rows(
            AES.sub_bytes(initial_state))), round_key=round_key)
        self.assertEqual(res, expected)

    def test_encrypt(self):
        plaintext = "theblockbreakers".encode().hex()
        key = "2b7e151628aed2a6abf7158809cf4f3c"
        expected = "c69f25d0025a9ef32393f63e2f05b747"
        self.assertEqual(AES(key).encrypt(plaintext), expected)

    def test_decrypt(self):
        plaintext = "theblockbreakers".encode().hex()
        key = "2b7e151628aed2a6abf7158809cf4f3c"
        service = AES(key)
        enc = service.encrypt(plaintext)
        self.assertEqual(service.decrypt(enc), plaintext)

    def test_variable_rounds(self):
        plaintext = "theblockbreakers".encode().hex()
        key = "2b7e151628aed2a6abf7158809cf4f3c"
        num_rounds = 3
        service = AES(key)
        enc = service.encrypt(plaintext, num_rounds)
        self.assertEqual(service.decrypt(enc, num_rounds), plaintext)


class Test_attack(unittest.TestCase):

    def test_delta_set(self):
        enc_service = AES(token_bytes(AES.BLOCK_SIZE).hex())
        delta_set_enc = setup(enc_service, num_rounds=3)
        for i in range(AES.BLOCK_SIZE):
            same_indices = [bytes.fromhex(enc)[i] for enc in delta_set_enc]
            self.assertEqual(reduce(lambda x, y: x ^ y, same_indices), 0)
        self.assertEqual(
            reduce(xor, map(bytes.fromhex, delta_set_enc)), b"\x00" * AES.BLOCK_SIZE)

    def test_reverse_state(self):
        key = token_bytes(AES.BLOCK_SIZE).hex()
        num_rounds = 4
        enc_service = AES(key)
        delta_set_enc = setup(enc_service, num_rounds=num_rounds)
        for pos in range(16):
            key_guess = bytes.fromhex(AES.key_expansion(key)[num_rounds])[pos]
            self.assertTrue(check_key_guess(
                reverse_state(
                    key_guess=key_guess,
                    pos=pos,
                    delta_set_enc=delta_set_enc
                )
            ))

    def test_recover_round_key(self):
        num_rounds = 4
        key = token_bytes(AES.BLOCK_SIZE).hex()
        enc_service = AES(key)
        last_round_key = AES.key_expansion(key)[num_rounds]
        cracked_round_key = recover_round_key(
            enc_service, num_rounds, disable_tqdm=True)
        self.assertEqual(cracked_round_key, last_round_key)

    def test_reverse_key_expansion(self):
        num_rounds = 4
        key = token_bytes(AES.BLOCK_SIZE).hex()
        last_round_key = AES.key_expansion(key)[num_rounds]
        recovered_key = reverse_key_expansion(last_round_key, num_rounds)
        self.assertEqual(recovered_key, key)


if __name__ == '__main__':
    unittest.main()
