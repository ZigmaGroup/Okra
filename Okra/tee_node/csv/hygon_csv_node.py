import json
import hashlib
import os
from datetime import datetime, timedelta
import cryptography.hazmat.backends as backends
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509

from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

import hetero_attestation_pb2_grpc
from hetero_attestation_pb2_grpc import TeeNodeService
from hetero_attestation_pb2 import RunStatus
from hetero_attestation_pb2 import TeeAttestationResponse
from hetero_attestation_pb2 import TeeAttestationRequest
from hetero_attestation_pb2 import HeteroAttestationResponse
from hetero_attestation_pb2 import HeteroAttestationRequest
from hetero_attestation_pb2 import RegisterNodeResponse
from hetero_attestation_pb2 import RegisterNodeRequest
from concurrent.futures import ThreadPoolExecutor
import argparse
import grpc
import logging
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# # autopep8: off
# import sys
# sys.path.append("../../wrapper/csv")
# print(sys.path)
# import csv_wrap
# # autopep8: on
# import csv_wrap
import csv_wrap
import function
import time
import key_exchange_pb2
import key_exchange_pb2_grpc


logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a')


class RegisterResult:
    def __init__(self, node_cert, ca_cert, pub_key, priv_key):
        self.node_cert = node_cert
        self.ca_cert = ca_cert
        self.pub_key = pub_key
        self.priv_key = priv_key



def gen_key_and_csr(common_name, org_name):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    pub_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "BJ"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "BJ"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName("mysite.com"),
        ]),
        critical=False,
        # Sign the CSR with our private key.
    ).sign(private_key, hashes.SHA256())
    csr_bytes = csr.public_bytes(serialization.Encoding.PEM)
    return (private_key_pem, pub_key_pem, csr_bytes)

class NodeClient:
    def __init__(self, node_id):
        self.node_id = node_id
        # 使用ECDSA生成私钥
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def get_public_key(self):
        print(self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex())
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def exchange_key(self, stub, retry=False):
        # 向服务端发送自己的公钥
        request = key_exchange_pb2.KeyExchangeRequest(
            node_id=self.node_id,
            public_key=self.get_public_key()
        )
        while True:
            response = stub.ExchangeKey(request)
            if response.public_key == b'second':
                print("收到 'second' 响应，等待对方节点的公钥...")
                time.sleep(2)
            else:
                print(f"收到对方公钥：{response.public_key.hex()}")
                received_pub_key = response.public_key
                break

        other_public_key = serialization.load_pem_public_key(received_pub_key)
        shared_secret = self.private_key.exchange(ec.ECDH(), other_public_key)

        # 通过PBKDF2从共享密钥派生最终密钥
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"salt",  # 使用更安全的随机salt
            iterations=100000,
        )
        final_key = kdf.derive(shared_secret)
        print(f"共享密钥：{final_key.hex()}")
        return final_key

def register_csv_node(node_id, common_name, org_name, center_service_addr):
    (priv_key, pub_key, csr_content) = gen_key_and_csr(common_name, org_name)
    # Reqeust to generate certificate.
    channel = grpc.insecure_channel(center_service_addr)
    stub = hetero_attestation_pb2_grpc.CenterServiceStub(channel)


    # 记录开始时间
    start_time = datetime.now()
    # 记录发送时间戳
    timestamp = int(datetime.now().timestamp() * 1000)  # 转换为毫秒
    logging.info(f"发送注册请求时间： {timestamp}")

    request = RegisterNodeRequest(node_id=node_id, csr_content=csr_content)

    # 记录请求数据量, 以字节为单位
    request_size = len(request.SerializeToString())
    logging.info(f"注册请求数据量: {request_size} bytes")

    response = stub.RegisterNode(request)

    # 记录响应数据量, 以字节为单位
    response_size = len(response.SerializeToString())
    logging.info(f"注册响应数据量: {response_size} bytes")

    # 记录收到响应的时间
    receive_response_time = datetime.now()
    receive_response_timestamp = int(receive_response_time.timestamp() * 1000)
    logging.info(f"接收注册响应时间 {receive_response_timestamp}")

    # 记录结束时间
    end_time = datetime.now()
    # 计算时间差
    elapsed_time = end_time - start_time
    logging.info(
        f"注册阶段总耗时: {elapsed_time.total_seconds()} seconds")


    logging.info(
        f"Register node to center attestation service {center_service_addr} finish.")


    return RegisterResult(response.node_cert, response.ca_cert, pub_key, priv_key)


class TeeNodeServiceForCSV(TeeNodeService):
    def __init__(self, node_id, priv_key_path, pub_key_path, node_cert_path,
                 ca_cert_path, center_service_addr, shared_key_path):
        self.priv_key_path = priv_key_path
        self.pub_key_path = pub_key_path
        self.ca_cert_path = ca_cert_path
        self.node_id = node_id
        self.node_cert_path = node_cert_path
        self.center_addr = center_service_addr
        self.shared_key_path = shared_key_path

    def CheckSignature(self, message, signature):
        with open(self.ca_cert_path, "rb") as f:
            ca_cert_bytes = f.read()

        ca_cert = load_pem_x509_certificate(ca_cert_bytes, default_backend())
        public_key = ca_cert.public_key()

        try:
            public_key.verify(signature, message,
                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                          salt_length=padding.PSS.MAX_LENGTH),
                              hashes.SHA256())
            return True
        except InvalidSignature:
            return False

    def IssueRemoteAttestation(self, request, response):

        # 记录收到nonce请求的时间戳
        receive_nonce_timestamp = int(datetime.now().timestamp() * 1000)
        logging.info(f"接收Nonce时间： {receive_nonce_timestamp}")

        # 记录请求数据量
        nonce_request_size = len(request.SerializeToString())
        logging.info(f"Nonce请求数据量: {nonce_request_size} bytes")
        # 解密nonce
        with open(self.shared_key_path, "rb") as f:
            shared_key = f.read()
        key = function.derive_fixed_key(shared_key)
        nonce = function.decrypt_message_ecb(key, request.nonce)

        with open(self.node_cert_path, "rb") as f:
            node_cert = f.read()

        proof, policy = csv_wrap.gen_csv_proof()

        proof_obj = json.loads(proof)
        report = proof_obj["report"]["json_report"]

        # 从文件中加载服务器的ca_cert从中提取RSA公钥，并提取n和e
        with open(self.ca_cert_path, "rb") as f:
            ca_cert_bytes = f.read()
        ca_cert = load_pem_x509_certificate(ca_cert_bytes, default_backend())
        server_rsa_pub_key = ca_cert.public_key()
        server_rsa_pub_key = server_rsa_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        server_rsa_pub_key = load_pem_public_key(server_rsa_pub_key, default_backend())
        n = server_rsa_pub_key.public_numbers().n
        e = server_rsa_pub_key.public_numbers().e

        # 生成盲化因子
        k = function.generate_blinding_factor()

        # 将report和nonce连接,哈希后进行盲化
        message = report + nonce.hex()
        message_hash = hashlib.sha256(message.encode("utf-8")).hexdigest()
        message_hash_int = int(message_hash, 16)


        blind_message = function.blind_hide_msg(message_hash_int, k, e, n)

        with open(self.priv_key_path, "rb") as f:
            priv_key = f.read()
        private_key = load_pem_private_key(priv_key, password=None)
        """原始签名"""
        """
        signature = private_key.sign(
            report.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        """

        # 对盲化消息、node_cert、node_id、"hetero_csv"进行签名
        sign_info = blind_message.to_bytes((blind_message.bit_length() + 7) // 8, byteorder="big")
        sign_info = sign_info + node_cert + self.node_id.encode("utf-8") + "hetero_csv".encode("utf-8")
        signature = private_key.sign(
            sign_info,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        digest = signature.hex()

        proof_obj["report"]["json_report_sig"] = digest
        proof = json.dumps(proof_obj)

        logging.info("Generate CSV proof finish.")
        logging.info("Request center attestation service to verify proof.")


        # 记录发送到中心认证服务的时间戳
        send_to_center_timestamp = int(datetime.now().timestamp() * 1000)
        logging.info(f"发送证明请求时间： {send_to_center_timestamp}")

        # Send to center attestation service.删除nonce
        verify_request = TeeAttestationRequest(
            tee_proof=proof,
            platform="hetero_csv",
            policy=policy,
            tee_node_id=self.node_id,
            attest_id=request.attest_id,
            challenger_node_id=request.node_id,
            tee_node_cert=node_cert,
            blind_message=str(blind_message).encode(),
            sign_info=sign_info)  # 传递盲化消息

        # 记录请求数据量
        verify_request_size = len(verify_request.SerializeToString())
        logging.info(f"证明请求数据量: {verify_request_size} bytes")


        if len(request.attachment) != 0:
            verify_request.attachment = request.attachment
            signature = private_key.sign(
                request.attachment,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            digest = signature.hex()
            verify_request.hex_attach_sig = digest
            logging.info(f"Generate signature of attachment finish.")

        channel = grpc.insecure_channel(self.center_addr)
        stub = hetero_attestation_pb2_grpc.CenterServiceStub(channel)

        verify_response = stub.VerifyTeeProof(verify_request)

        # 记录响应数据量
        verify_response_size = len(verify_response.SerializeToString())
        logging.info(f"证明响应数据量: {verify_response_size} bytes")

        # 记录收到中心认证服务的时间戳
        receive_from_center_timestamp = int(datetime.now().timestamp() * 1000)
        logging.info(f"从中心节点接收证明响应时间： {receive_from_center_timestamp}")

        if verify_response.status.error:
            response = HeteroAttestationResponse(
                status=RunStatus(error=True, msg=verify_response.status.msg))
            logging.error(
                f"Center attestion service verify failed, {verify_response.status.msg}")
            return response

        logging.info("Center attestation service return verify result.")

        digest_obj = json.loads(verify_response.service_digest)
        signature = bytes.fromhex(digest_obj["signature"])

        # 验证签名的消息增加blind_message，删除nonce
        message = verify_request.tee_proof + \
                  verify_response.verify_result + \
                  str(blind_message) + \
                  hashlib.sha256(request.attachment).hexdigest()
        message = message.encode("utf-8")

        sha256_result = hashlib.sha256(message).hexdigest()
        logging.info(f"SHA256 of message is {sha256_result}")

        if not self.CheckSignature(message, signature):
            response = HeteroAttestationResponse(
                status=RunStatus(error=True,
                                 msg="Verify signature from center service failed."))
            logging.error("Verify signature failed.")
            return response

        logging.info("Signature verify finish.")

        # 解除盲化
        blind_signature = int.from_bytes(verify_response.blind_signature, byteorder="big")
        unblinded_signature = function.blind_retrieve_sig(blind_signature, k, n)
        # 验证解除盲化后的签名
        verify_result = function.verify_blind_sig(message_hash_int, unblinded_signature, e, n)
        # 发送的消息增加盲签名
        # 验证通过后转发响应
        if verify_result:

            response = HeteroAttestationResponse(
                verify_result=verify_response.verify_result,
                tee_proof=proof.encode("utf-8"), signature=digest_obj["signature"],
                nonce=nonce,
                status=RunStatus(error=False),
                blind_message = str(blind_message).encode(),
                blind_signature = str(unblinded_signature).encode()) # 增加盲签名
            
            # 记录发送远程证明响应的数据量
            response_size = len(response.SerializeToString())
            logging.info(f"转发证明响应数据量: {response_size} bytes")

            # 记录发送远程证明响应的时间戳
            send_attestation_response_timestamp = int(datetime.now().timestamp() * 1000)
            logging.info(f"转发证明响应时间： {send_attestation_response_timestamp}")

            return response
        else:
            logging.error("Verify signature failed.")


def setup_cmdline_args():
    parser = argparse.ArgumentParser(description='CSV node service.')
    parser.add_argument("--config", required=True, help="Path of config file.")
    return parser


if __name__ == '__main__':
    parser = setup_cmdline_args()
    args = parser.parse_args()
    with open(args.config, "r") as f:
        conf_obj = json.load(f)

    logging.info(conf_obj)
    node_id = conf_obj["node_id"]
    common_name = conf_obj["csr_field"]["common_name"]
    org_name = conf_obj["csr_field"]["organization_name"]
    attest_center_info = conf_obj["center_attestation_service"]
    center_key_exchange_info = conf_obj["center_key_exchange_service"]
    result = register_csv_node(node_id, common_name, org_name, attest_center_info)
    priv_key_path = conf_obj["cert_and_key_file_path"] + "/priv_key"
    pub_key_path = conf_obj["cert_and_key_file_path"] + "/pub_key"
    node_cert_path = conf_obj["cert_and_key_file_path"] + "/node_cert"
    ca_cert_path = conf_obj["cert_and_key_file_path"] + "/ca_cert"
    shared_key_path = conf_obj["cert_and_key_file_path"] + "/shared_key"

    node_a = NodeClient(node_id)
    with grpc.insecure_channel(center_key_exchange_info) as channel:
        stub = key_exchange_pb2_grpc.KeyExchangeServiceStub(channel)
        # 节点A
        shared_key = node_a.exchange_key(stub)


    with open(node_cert_path, "wb") as f:
        f.write(result.node_cert)

    with open(ca_cert_path, "wb") as f:
        f.write(result.ca_cert)

    with open(priv_key_path, "wb") as f:
        f.write(result.priv_key)

    with open(pub_key_path, "wb") as f:
        f.write(result.pub_key)

    with open(shared_key_path, "wb") as f:
        f.write(shared_key)


    server = grpc.server(ThreadPoolExecutor(max_workers=10))
    service_impl = TeeNodeServiceForCSV(node_id, priv_key_path,
                                        pub_key_path,
                                        node_cert_path,
                                        ca_cert_path,
                                        attest_center_info,
                                        shared_key_path)

    hetero_attestation_pb2_grpc.add_TeeNodeServiceServicer_to_server(
        service_impl, server)
    port = conf_obj["listen_port"]
    server.add_insecure_port("[::]:" + port)
    server.start()

    logging.info("The Node service is running. "
                 f'listen port: {port}')
    server.wait_for_termination()
