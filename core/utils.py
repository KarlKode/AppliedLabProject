from binascii import hexlify, unhexlify
import M2Crypto
import os


def encrypt(public_key_file, pt):
    # Generate random values for the AES encryption
    aes_key = os.urandom(32)
    aes_key_hex = hexlify(aes_key)
    aes_iv = os.urandom(32)
    aes_iv_hex = hexlify(aes_iv)
    # Encrypt the plaintext with AES 256
    aes = M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=aes_key, iv=aes_iv, op=1)
    ct = aes.update(pt) + aes.final()
    # MAC the plaintext
    mac = M2Crypto.EVP.hmac(aes_key, ct)
    # Encrypt the AES key and IV with the public key
    public_key = M2Crypto.RSA.load_pub_key(public_key_file)
    key_ct = public_key.public_encrypt(aes_key_hex + aes_iv_hex, M2Crypto.RSA.pkcs1_oaep_padding)
    return key_ct, ct, mac


def decrypt(private_key_file, key_ct, ct, mac):
    # Decrypt the AES key and IV with the private key
    private_key = M2Crypto.RSA.load_key(private_key_file)
    key_plain = private_key.private_decrypt(key_ct, M2Crypto.RSA.pkcs1_oaep_padding)
    # Check the key length (two 32 byte keys hexlified are 128 bytes) and unhexlify them
    if len(key_plain) != 128:
        return None
    aes_key = unhexlify(key_plain[:64])
    aes_iv = unhexlify(key_plain[64:])
    # Decrypt the ciphertext
    aes = M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=aes_key, iv=aes_iv, op=0)
    pt = aes.update(ct) + aes.final()
    # Check the MAC
    if mac != M2Crypto.EVP.hmac(aes_key, ct):
        return None
    return pt


def main():
    key_ct, ct, mac = encrypt("backup_pub.key", "tesfasdfsadft")
    plain = decrypt("backup.key", key_ct, ct, mac)
    print plain


if __name__ == "__main__":
    main()