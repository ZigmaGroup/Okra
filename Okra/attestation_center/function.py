from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib


def ecdh_shared_key(private_key, peer_public_key):
    """
    使用ECDH算法计算共享密钥。

    :param private_key: 自己的私钥 (ec.EllipticCurvePrivateKey)
    :param peer_public_key: 对方的公钥 (ec.EllipticCurvePublicKey)
    :return: 共享密钥 (bytes)
    """
    # 使用ECDH协议计算共享密钥
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key

def blind_hide_msg(msg, factor, e, n):
    """盲化消息"""
    return (msg * pow(factor, e, n))

def derive_fixed_key(shared_key, length=16):
    """
    从共享密钥派生固定长度的对称密钥。

    :param shared_key: ECDH 计算出的共享密钥 (bytes)
    :param length: 对称密钥长度（字节），默认 16 字节 (128 位)
    :return: 固定长度的对称密钥 (bytes)
    """
    return hashlib.sha256(shared_key).digest()[:length]

def encrypt_message_ecb(key, plaintext):
    """
    使用 AES-ECB 模式加密消息。

    :param key: 对称密钥 (bytes)
    :param plaintext: 明文消息 (str)
    :return: 密文 (bytes)
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    # 填充明文到 16 字节的倍数
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([padding_length] * padding_length)
    ciphertext = cipher.update(padded_plaintext) + cipher.finalize()
    return ciphertext

def decrypt_message_ecb(key, ciphertext):
    """
    使用 AES-ECB 模式解密消息。

    :param key: 对称密钥 (bytes)
    :param ciphertext: 密文消息 (bytes)
    :return: 解密后的明文消息 (str)
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    padded_plaintext = cipher.update(ciphertext) + cipher.finalize()
    # 去除填充
    padding_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_length]
    return plaintext

def blind_signature(blind_msg, d, n):
    """签名盲化消息"""
    return pow(blind_msg, d, n)


def generate_blinding_factor():
    """生成盲化因子"""
    while True:
        prime_candidate = secrets.randbits(1024)
        if is_prime(prime_candidate):
            return prime_candidate


def is_prime(n, k=5):
    """Miller-Rabin算法判断是否是素数"""
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    s, d = 0, n - 1
    while d % 2 == 0:
        s, d = s + 1, d // 2
    for _ in range(k):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_rsa_key_pair():
    """生成 RSA 密钥对"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    n = public_key.public_numbers().n
    return private_key, public_key


def save_key_to_file(key, filename):
    """保存私钥到文件"""
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as f:
        f.write(pem)


def load_key_from_file(filename):
    """从文件中加载密钥"""
    with open(filename, 'rb') as f:
        pem = f.read()
        return serialization.load_pem_private_key(pem, password=None)


def blind_retrieve_sig(blind_sig, factor, n):
    """解除盲化后的签名"""
    inverse = pow(factor, -1, n)
    return (blind_sig * inverse) % n


def verify_blind_sig(msg, unblinded_signature, e, n):
    """验证签名"""
    if pow(unblinded_signature, e, n) == msg:
        return True
    return False
