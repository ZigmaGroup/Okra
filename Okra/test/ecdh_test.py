import os

from Blind_RSA.blind_rsa import *

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

# 测试
if __name__ == "__main__":
    # 生成用户 A 的密钥对
    private_key_A = ec.generate_private_key(ec.SECP256R1())
    public_key_A = private_key_A.public_key()

    # 将public_key_A序列化为bytes
    public_key_A_bytes = public_key_A.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"public_key_A_bytes: {public_key_A_bytes}")

    # 生成用户 B 的密钥对
    private_key_B = ec.generate_private_key(ec.SECP256R1())
    public_key_B = private_key_B.public_key()

    # 用户 A 计算共享密钥
    shared_key_A = ecdh_shared_key(private_key_A, public_key_B)

    # 用户 B 计算共享密钥
    shared_key_B = ecdh_shared_key(private_key_B, public_key_A)

    # 验证共享密钥是否一致
    assert shared_key_A == shared_key_B, "共享密钥不匹配！"
    print(f"共享密钥: {shared_key_A.hex()}")

    # 使用共享密钥加密消息
    msg = 123456
    # msg 转换为bytes
    msg = str(msg).encode()

    print(f"原始消息: {msg}")
    # 使用共享密钥加密消息
    key = derive_fixed_key(shared_key_A)
    ciphertext = encrypt_message_ecb(key, msg)
    print(f"加密后的消息: {ciphertext.hex()}")
    # 使用共享密钥解密消息
    decrypted_msg = decrypt_message_ecb(key, ciphertext)
    print(f"解密后的消息: {decrypted_msg}")
