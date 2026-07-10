#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SM9 Demo Script
# Tests sign/verify and encrypt/decrypt through the cryptography interface.

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pysmx.SM9._SM9 import (
    Sign, Verify, Encrypt, Decrypt,
    generate_master_key,
    generate_user_sign_key,
    generate_user_enc_key,
    _g2_scalar_mult, _g2_to_affine,
    _g1_scalar_mult, _g1_to_affine,
    _sm9_P2, _sm9_P1x, _sm9_P1y,
)


def test_sign_verify():
    print("=== SM9 Sign / Verify ===")
    ke, P_pub_e = generate_master_key()

    # Create signature master public key
    P2 = (
        (_sm9_P2[0], _sm9_P2[1]),
        (_sm9_P2[2], _sm9_P2[3]),
    )
    P_pub_s_jac = _g2_scalar_mult(ke, P2)
    P_pub_s = _g2_to_affine(P_pub_s_jac)

    ID_A = b'alice@sm9.test'
    d_A = generate_user_sign_key(ke, ID_A, hid=0x01)

    message = b'Hello SM9 Signature!'
    sig = Sign(message, d_A, P_pub_s, hid=0x01)
    print(f"  Signature: {len(sig)} bytes")

    result = Verify(message, sig, ID_A, P_pub_s, hid=0x01)
    print(f"  SM9 sign/verify: {'OK' if result else 'FAIL'}")
    return result


def test_encrypt_decrypt():
    print("\n=== SM9 Encrypt / Decrypt ===")
    ke, P_pub_e = generate_master_key()

    ID_B = b'bob@sm9.test'
    d_B = generate_user_enc_key(ke, ID_B, hid=0x03)

    plaintext = b'Confidential SM9 message'
    ciphertext = Encrypt(plaintext, ID_B, P_pub_e, hid=0x03)
    print(f"  Ciphertext: {len(ciphertext)} bytes")

    decrypted = Decrypt(ciphertext, d_B, ID_B, hid=0x03)
    if decrypted is not None:
        print(f"  SM9 encrypt/decrypt: {'OK' if decrypted == plaintext else 'FAIL'}")
        print(f"  Decrypted message: {decrypted.decode() if isinstance(decrypted, bytes) else decrypted}")
    else:
        print("  SM9 encrypt/decrypt: FAIL (None result)")


def test_kem():
    print("\n=== SM9 KEM ===")
    from pysmx.SM9._SM9 import KEM_Encapsulate, KEM_Decapsulate

    ke, P_pub_e = generate_master_key()
    ID_B = b'carol@sm9.test'
    d_B = generate_user_enc_key(ke, ID_B, hid=0x02)

    klen = 32
    K_enc, C = KEM_Encapsulate(ID_B, P_pub_e, klen, hid=0x02)
    K_dec = KEM_Decapsulate(C, d_B, ID_B, klen, hid=0x02)
    print(f"  KEM: {'OK' if K_enc == K_dec else 'FAIL'}")


if __name__ == '__main__':
    try:
        test_sign_verify()
        test_encrypt_decrypt()
        test_kem()
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
