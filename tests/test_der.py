import unittest

from mailposture.der import rsa_modulus_bits

from _keys import pkcs1_b64, spki_b64


class DerTests(unittest.TestCase):
    def test_spki_1024(self):
        self.assertEqual(rsa_modulus_bits(spki_b64(1024)), 1024)

    def test_spki_2048(self):
        self.assertEqual(rsa_modulus_bits(spki_b64(2048)), 2048)

    def test_spki_4096(self):
        self.assertEqual(rsa_modulus_bits(spki_b64(4096)), 4096)

    def test_pkcs1_layout(self):
        self.assertEqual(rsa_modulus_bits(pkcs1_b64(2048)), 2048)

    def test_whitespace_and_missing_padding(self):
        key = spki_b64(1024)
        chopped = key[:len(key) // 2] + "\n " + key[len(key) // 2:]
        self.assertEqual(rsa_modulus_bits(chopped), 1024)

    def test_empty_key_rejected(self):
        with self.assertRaises(ValueError):
            rsa_modulus_bits("")

    def test_garbage_rejected(self):
        with self.assertRaises(ValueError):
            rsa_modulus_bits("!!!not-base64!!!")


if __name__ == "__main__":
    unittest.main()
