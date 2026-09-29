#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""SM2 signature with the GM/T 0003 'ZA||M' digest structure (uid parameter).

When ``uid`` is given, Sign/Verify compute e = SM3(ZA || M) where
ZA = SM3(ENTL||IDA||a||b||xG||yG||xA||yA); when omitted the legacy behaviour
(E taken as the digest itself) is preserved.
"""

import unittest

try:  # third-party reference implementation, only used for interoperability
    from gmssl import sm2 as gm_sm2
    HAVE_GMSSL = True
except ImportError:  # pragma: no cover
    HAVE_GMSSL = False

try:  # cryptography bindings are optional (pysmx/SM2 swallows the ImportError)
    from cryptography.exceptions import InvalidSignature
    from pysmx.SM2 import (
        SM2EllipticCurve,
        SM2EllipticCurvePrivateKey,
        SM2SM3SignatureAlgorithm,
        SM2SHA256SignatureAlgorithm,
    )
    HAVE_SM2_CLASSES = True
except ImportError:  # pragma: no cover
    HAVE_SM2_CLASSES = False


class TestSM2Uid(unittest.TestCase):
    # GB/T 32918.2-2016 standard key pair
    D = (
        "3945208F7B2144B13F36E38AC6D39F95"
        "889393692860B51A42FB81EF4DF7C5B8"
    )
    PA = (
        "09F9DF311E5421A150DD7D161E4BC5C6"
        "72179FAD1833FC076BB08FF356F35020"
        "CCEA490CE26775A52DC6EA718CC1AA60"
        "0AED05FBF35E084A6632F6072DA9AD13"
    )
    # Fixed random number so the signature is reproducible
    K = "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21"

    MSG = b"message digest"
    MSG_TEXT = "message digest"
    DEFAULT_UID = "1234567812345678"
    CUSTOM_UID = "ALICE123@YAHOO.COM"

    # Pinned against the gmssl reference implementation (see test_cross_*)
    ZA_DEFAULT = (
        "b2e14c5c79c6df5b85f4fe7ed8db7a26"
        "2b9da7e07ccb0ea9f4747b8ccda8a4f3"
    )
    SIG_DEFAULT = (
        "f5a03b0648d2c4630eeac513e1bb81a1"
        "5944da3827d5b74143ac7eaceee720b3"
        "b1b6aa29df212fd8763182bc0d421ca1"
        "bb9038fd1f7f42d4840b69c485bbc1aa"
    )

    def setUp(self):
        import pysmx.SM2 as sm2
        from pysmx.SM2._SM2 import get_za, kG, sm2_G
        self.sm2 = sm2
        self.get_za = get_za
        self.public_key_of = lambda d: kG(int(d, 16), sm2_G, 64)

    # ---- ZA value ----

    def test_public_key_matches_standard_vector(self):
        self.assertEqual(self.public_key_of(self.D), self.PA.lower())

    def test_za_known_answer(self):
        self.assertEqual(self.get_za(self.DEFAULT_UID, self.PA, 64), self.ZA_DEFAULT)

    def test_za_accepts_bytes_key_and_uid(self):
        self.assertEqual(
            self.get_za(self.DEFAULT_UID.encode(), bytes.fromhex(self.PA), 64),
            self.ZA_DEFAULT,
        )

    def test_za_depends_on_uid(self):
        self.assertNotEqual(
            self.get_za(self.DEFAULT_UID, self.PA, 64),
            self.get_za(self.CUSTOM_UID, self.PA, 64),
        )

    def test_za_depends_on_public_key(self):
        other_pk, _ = self.sm2.generate_keypair(64)
        self.assertNotEqual(
            self.get_za(self.DEFAULT_UID, self.PA, 64),
            self.get_za(self.DEFAULT_UID, other_pk, 64),
        )

    def test_za_concatenation_layout(self):
        """ZA must be SM3 over ENTL||ID||a||b||xG||yG||xA||yA."""
        from pysmx.SM3 import hexdigest
        from pysmx.SM2._SM2 import sm2_a, sm2_b, sm2_G

        uid = self.DEFAULT_UID.encode()
        form = '%064x'
        payload = (
            bytes.fromhex('%04x' % (len(uid) * 8))
            + uid
            + bytes.fromhex(form % sm2_a)
            + bytes.fromhex(form % sm2_b)
            + bytes.fromhex(sm2_G)
            + bytes.fromhex(self.PA)
        )
        self.assertEqual(hexdigest(payload), self.ZA_DEFAULT)

    def test_za_rejects_bad_arguments(self):
        with self.assertRaises(ValueError):
            self.get_za(1, self.PA, 64)
        with self.assertRaises(ValueError):
            self.get_za(self.DEFAULT_UID, 1, 64)
        with self.assertRaises(ValueError):
            self.get_za(b'x' * 8192, self.PA, 64)  # ENTL overflows 2 bytes

    # ---- sign / verify round trip ----

    def test_sign_verify_with_uid(self):
        sig = self.sm2.Sign(self.MSG, self.D, self.K, 64, uid=self.DEFAULT_UID)
        self.assertIsInstance(sig, bytes)
        self.assertEqual(len(sig), 64)
        self.assertTrue(self.sm2.Verify(sig, self.MSG, self.PA, 64, uid=self.DEFAULT_UID))

    def test_sign_verify_text_message(self):
        """str message must yield the same result as bytes."""
        sig_b = self.sm2.Sign(self.MSG, self.D, self.K, 64, uid=self.DEFAULT_UID)
        sig_s = self.sm2.Sign(self.MSG_TEXT, self.D, self.K, 64, uid=self.DEFAULT_UID)
        self.assertEqual(sig_b, sig_s)
        self.assertTrue(self.sm2.Verify(sig_s, self.MSG_TEXT, self.PA, 64, uid=self.DEFAULT_UID))

    def test_sign_verify_hexstr_message(self):
        sig = self.sm2.Sign(self.MSG.hex(), self.D, self.K, 64, Hexstr=1, uid=self.DEFAULT_UID)
        self.assertEqual(sig, self.sm2.Sign(self.MSG, self.D, self.K, 64, uid=self.DEFAULT_UID))
        self.assertTrue(
            self.sm2.Verify(sig, self.MSG.hex(), self.PA, 64, Hexstr=1, uid=self.DEFAULT_UID)
        )

    def test_signature_known_answer(self):
        sig = self.sm2.Sign(self.MSG, self.D, self.K, 64, uid=self.DEFAULT_UID)
        self.assertEqual(sig.hex(), self.SIG_DEFAULT)

    def test_uid_mode_differs_from_legacy(self):
        """uid=None keeps taking E as the digest; uid=... must not silently alias it."""
        sig_uid = self.sm2.Sign(self.MSG, self.D, self.K, 64, uid=self.DEFAULT_UID)
        sig_legacy = self.sm2.Sign(self.MSG, self.D, self.K, 64)
        self.assertNotEqual(sig_uid, sig_legacy)
        self.assertFalse(self.sm2.Verify(sig_uid, self.MSG, self.PA, 64))
        self.assertFalse(self.sm2.Verify(sig_legacy, self.MSG, self.PA, 64, uid=self.DEFAULT_UID))

    # ---- negative cases ----

    def test_wrong_uid_fails(self):
        sig = self.sm2.Sign(self.MSG, self.D, self.K, 64, uid=self.CUSTOM_UID)
        self.assertFalse(self.sm2.Verify(sig, self.MSG, self.PA, 64, uid=self.DEFAULT_UID))

    def test_tampered_message_fails(self):
        sig = self.sm2.Sign(self.MSG, self.D, self.K, 64, uid=self.DEFAULT_UID)
        self.assertFalse(self.sm2.Verify(sig, b"message diges!", self.PA, 64, uid=self.DEFAULT_UID))

    def test_wrong_public_key_fails(self):
        other_pk, _ = self.sm2.generate_keypair(64)
        sig = self.sm2.Sign(self.MSG, self.D, self.K, 64, uid=self.DEFAULT_UID)
        self.assertFalse(self.sm2.Verify(sig, self.MSG, other_pk, 64, uid=self.DEFAULT_UID))

    def test_generated_keypair_roundtrip(self):
        pk, sk = self.sm2.generate_keypair(64)
        sig = self.sm2.Sign(self.MSG, sk, self.K, 64, uid=self.DEFAULT_UID)
        self.assertTrue(self.sm2.Verify(sig, self.MSG, pk, 64, uid=self.DEFAULT_UID))

    # ---- interoperability ----

    @unittest.skipUnless(HAVE_GMSSL, 'gmssl not installed')
    def test_interop_signature_matches_gmssl(self):
        ref = gm_sm2.CryptSM2(private_key=self.D, public_key=self.PA)
        self.assertEqual(
            ref.sign_with_sm3(self.MSG, random_hex_str=self.K),
            self.sm2.Sign(self.MSG, self.D, self.K, 64, uid=self.DEFAULT_UID).hex(),
        )

    @unittest.skipUnless(HAVE_GMSSL, 'gmssl not installed')
    def test_interop_verify_cross(self):
        """Each implementation must accept the other's signature."""
        ref = gm_sm2.CryptSM2(private_key=self.D, public_key=self.PA)
        ours = self.sm2.Sign(self.MSG, self.D, self.K, 64, uid=self.DEFAULT_UID)
        theirs = ref.sign_with_sm3(self.MSG, random_hex_str=self.K)
        self.assertTrue(ref.verify_with_sm3(ours.hex(), self.MSG))
        self.assertTrue(self.sm2.Verify(bytes.fromhex(theirs), self.MSG, self.PA, 64,
                                        uid=self.DEFAULT_UID))


@unittest.skipUnless(HAVE_SM2_CLASSES, 'cryptography SM2 bindings not available')
class TestSM2UidClassApi(unittest.TestCase):
    """The cryptography-style classes must expose the same uid behaviour."""
    D = TestSM2Uid.D
    PA = TestSM2Uid.PA
    MSG = TestSM2Uid.MSG
    DEFAULT_UID = TestSM2Uid.DEFAULT_UID
    CUSTOM_UID = TestSM2Uid.CUSTOM_UID

    def setUp(self):
        self.curve = SM2EllipticCurve()
        self.sk = SM2EllipticCurvePrivateKey(
            self.curve, bytes.fromhex(self.D), bytes.fromhex(self.PA)
        )
        self.pk = self.sk.public_key()
        self.alg = SM2SM3SignatureAlgorithm()

    def test_sign_verify_with_uid(self):
        sig = self.sk.sign(self.MSG, self.alg, uid=self.DEFAULT_UID)
        self.assertEqual(len(sig), 64)
        self.assertIsNone(self.pk.verify(sig, self.MSG, self.alg, uid=self.DEFAULT_UID))

    def test_default_keeps_digest_mode(self):
        sig = self.sk.sign(self.MSG, self.alg)
        self.assertIsNone(self.pk.verify(sig, self.MSG, self.alg))

    def test_uid_mode_incompatible_with_legacy(self):
        sig = self.sk.sign(self.MSG, self.alg, uid=self.DEFAULT_UID)
        with self.assertRaises(InvalidSignature):
            self.pk.verify(sig, self.MSG, self.alg)

    def test_wrong_uid_fails(self):
        sig = self.sk.sign(self.MSG, self.alg, uid=self.CUSTOM_UID)
        with self.assertRaises(InvalidSignature):
            self.pk.verify(sig, self.MSG, self.alg, uid=self.DEFAULT_UID)

    def test_tampered_message_fails(self):
        sig = self.sk.sign(self.MSG, self.alg, uid=self.DEFAULT_UID)
        with self.assertRaises(InvalidSignature):
            self.pk.verify(sig, b'message diges!', self.alg, uid=self.DEFAULT_UID)

    def test_uid_requires_sm3(self):
        with self.assertRaises(ValueError):
            self.sk.sign(self.MSG, SM2SHA256SignatureAlgorithm(), uid=self.DEFAULT_UID)
        sig = self.sk.sign(self.MSG, self.alg, uid=self.DEFAULT_UID)
        with self.assertRaises(ValueError):
            self.pk.verify(sig, self.MSG, SM2SHA256SignatureAlgorithm(),
                           uid=self.DEFAULT_UID)


if __name__ == '__main__':
    unittest.main()
