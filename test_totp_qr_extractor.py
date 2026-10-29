"""Tests sans dépendance : python -m unittest  (données 100 % synthétiques)."""
import base64
import unittest
import urllib.parse

import totp_qr_extractor as ga2bw


def _v(n):
    out = b""
    while True:
        b, n = n & 127, n >> 7
        if n:
            out += bytes([b | 128])
        else:
            return out + bytes([b])


def _ld(field, data):
    return _v(field << 3 | 2) + _v(len(data)) + data


def _account(secret, name, issuer, alg, digits, typ):
    return (_ld(1, secret) + _ld(2, name.encode()) + _ld(3, issuer.encode())
            + _v(4 << 3) + _v(alg) + _v(5 << 3) + _v(digits) + _v(6 << 3) + _v(typ))


def _uri(payload):
    return "otpauth-migration://offline?data=" + urllib.parse.quote(base64.b64encode(payload).decode())


class ParseTest(unittest.TestCase):
    def test_accounts_and_batch(self):
        payload = (_ld(1, _account(b"Hello!\xde\xad\xbe\xef", "alice@x.fr", "GitHub", 1, 1, 2))
                   + _ld(1, _account(b"12345678901234567890", "bob", "", 2, 2, 1))
                   + _v(3 << 3) + _v(3) + _v(4 << 3) + _v(1) + _v(5 << 3) + _v(42))
        accs, size, idx, bid = ga2bw.parse_migration_uri(_uri(payload))
        self.assertEqual((size, idx, bid), (3, 1, 42))
        a, b = accs
        self.assertEqual((a.issuer, a.name, a.secret, a.type, a.algorithm, a.digits),
                         ("GitHub", "alice@x.fr", "JBSWY3DPEHPK3PXP", "TOTP", "SHA1", 6))
        self.assertEqual((b.type, b.algorithm, b.digits), ("HOTP", "SHA256", 8))
        self.assertTrue(a.uri.startswith("otpauth://totp/GitHub:alice@x.fr?secret=JBSWY3DPEHPK3PXP"))

    def test_rejects_other_uri(self):
        with self.assertRaises(ValueError):
            ga2bw.parse_migration_uri("https://example.com")


class OtpauthTest(unittest.TestCase):
    def test_plain_totp(self):
        accs, size, idx, bid = ga2bw.parse_uri(
            "otpauth://totp/ACME%20Co:john@example.com?secret=jbsw y3dp-ehpk3pxp&issuer=ACME%20Co&digits=8&algorithm=SHA256")
        a = accs[0]
        self.assertEqual((a.issuer, a.name, a.secret, a.digits, a.algorithm, size),
                         ("ACME Co", "john@example.com", "JBSWY3DPEHPK3PXP", 8, "SHA256", 1))

    def test_plain_hotp_counter(self):
        a = ga2bw.parse_uri("otpauth://hotp/bob?secret=JBSWY3DPEHPK3PXP&counter=7")[0][0]
        self.assertEqual((a.type, a.counter, a.issuer), ("HOTP", 7, ""))

    def test_bad_secret(self):
        with self.assertRaises(ValueError):
            ga2bw.parse_uri("otpauth://totp/x?secret=!!!")


if __name__ == "__main__":
    unittest.main()
