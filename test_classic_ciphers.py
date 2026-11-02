import unittest

import classic_ciphers as cc

FR_TEXT = ("Les chats dorment sur le canapé pendant que la pluie tombe doucement sur "
           "les toits de la ville et que tout le monde attend le retour du soleil")


class TestCaesar(unittest.TestCase):
    def test_known_value(self):
        self.assertEqual(cc.caesar("Hello, World!", 3), "Khoor, Zruog!")

    def test_roundtrip(self):
        self.assertEqual(cc.caesar(cc.caesar(FR_TEXT, 11), -11), FR_TEXT)

    def test_non_letters_unchanged(self):
        self.assertEqual(cc.caesar("é 42 !", 5), "é 42 !")

    def test_crack_finds_the_shift(self):
        encrypted = cc.caesar(FR_TEXT, 7)
        shift, plain, _ = cc.crack_caesar(encrypted, "fr")[0]
        self.assertEqual(shift, 7)
        self.assertEqual(plain, FR_TEXT)


class TestVigenere(unittest.TestCase):
    def test_known_value(self):
        self.assertEqual(cc.vigenere("ATTACKATDAWN", "LEMON"), "LXFOPVEFRNHR")

    def test_decrypt(self):
        self.assertEqual(cc.vigenere("LXFOPVEFRNHR", "LEMON", decrypt=True), "ATTACKATDAWN")

    def test_roundtrip_with_spaces_and_case(self):
        msg = "Attack at dawn, 6 h !"
        self.assertEqual(cc.vigenere(cc.vigenere(msg, "lemon"), "lemon", decrypt=True), msg)

    def test_empty_key_refused(self):
        with self.assertRaises(ValueError):
            cc.vigenere("abc", "123")


class TestFrequencies(unittest.TestCase):
    def test_sum_is_about_100(self):
        self.assertAlmostEqual(sum(cc.frequencies(FR_TEXT).values()), 100, delta=0.5)

    def test_accents_count_as_base_letter(self):
        self.assertEqual(cc.letter_counts("éé")["e"], 2)


if __name__ == "__main__":
    unittest.main()
