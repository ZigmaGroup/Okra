from http.client import responses

import grpc
import json
import hashlib
import os
from hetero_attestation_pb2 import RegisterNodeRequest
from hetero_attestation_pb2 import RegisterNodeResponse
from hetero_attestation_pb2 import HeteroAttestationRequest
from hetero_attestation_pb2 import HeteroAttestationResponse
from hetero_attestation_pb2 import TeeAttestationRequest
from hetero_attestation_pb2 import TeeAttestationResponse
from hetero_attestation_pb2 import RunStatus
from hetero_attestation_pb2_grpc import TeeNodeService
import hetero_attestation_pb2_grpc

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import cryptography.hazmat.backends as backends
from datetime import datetime, timedelta
import blind_rsa
import key_exchange_pb2
import key_exchange_pb2_grpc

import logging
logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a'
                    )


class HeteroAttestationIssuer:
    def __init__(self, ca_cert_path, attest_id, node_id, tee_node_addr, nonce, nonce_no_crypto):
        self.attest_id = attest_id
        self.node_id = node_id
        self.tee_node_addr = tee_node_addr
        self.nonce = nonce
        self.ca_cert_path = ca_cert_path
        self.nonce_no_crypto = nonce_no_crypto

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

    def IssueHeteroAttestation(self):
        channel = grpc.insecure_channel(self.tee_node_addr)
        stub = hetero_attestation_pb2_grpc.TeeNodeServiceStub(channel)

        request = HeteroAttestationRequest(attest_id=self.attest_id,
                                           nonce=self.nonce,
                                           node_id=self.node_id,
                                           attachment="test".encode("utf-8"))


        # 记录开始时间
        start_time = datetime.now()

        # 记录发送nonce时间戳
        send_nonce_timestamp = int(datetime.now().timestamp() * 1000)
        logging.info(f"发送Nonce请求时间： {send_nonce_timestamp}")

        response = stub.IssueRemoteAttestation(request)

        # 记录接收远程证明响应时间戳
        receive_attestation_response_timestamp = int(datetime.now().timestamp() * 1000)
        logging.info(f"接收远程证明响应时间: {receive_attestation_response_timestamp}")

        if response.status.error == True:
            logging.error(
                f"Error from {self.tee_node_addr}: {response.status.msg}")
            return False
        
        

        proof = response.tee_proof
        verify_result = response.verify_result
        signature = bytes.fromhex(response.signature)
        unblinded_signature = int(response.blind_signature.decode(), 10)

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


        message = response.tee_proof + response.verify_result + response.blind_message.decode() + \
            hashlib.sha256(request.attachment).hexdigest()
        message = message.encode("utf-8")
        tee_proof = response.tee_proof
        proof_obj = json.loads(tee_proof)
        report = proof_obj["report"]["json_report"]
        m = report + self.nonce_no_crypto.hex()
        message_hash = hashlib.sha256(m.encode("utf-8")).hexdigest()
        message_hash_int = int(message_hash, 16)

        if response.nonce.hex() != self.nonce_no_crypto.hex():
            logging.error("Nonce mismatch error.")
            return False

        if not self.CheckSignature(message, signature):
            logging.error("Verify signature failed.")
            return False
        """暂时未添加盲签名验证"""
        if not blind_rsa.verify_blind_sig(message_hash_int, unblinded_signature, e, n):
            logging.error("Verify blind signature failed.")
            return False
        else:
            logging.info("Verify signature finish.")

        # 记录结束时间
        end_time = datetime.now()
        # 记录结束时间戳
        end_timestamp = int(datetime.now().timestamp() * 1000)
        logging.info(f"End timestamp: {end_timestamp}")
        total_elapsed_time = end_time - start_time
        logging.info(f"远程证明总耗时: {total_elapsed_time.total_seconds()} seconds")


        if verify_result == "pass":
            logging.info("Verify passed.")
            return True
        else:
            logging.error("Verify failed.")
            return False


if __name__ == '__main__':
    ca_cert_path = "/attestation/ca_cert"
    node_id = "hygon_csv_node"
    tee_node_addr = "10.93.116.55:40070"
    nonce = os.urandom(12)
    nonce_no_crypto = nonce

    # 读取shared_key
    shared_key = open("/attestation/shared_key", "rb").read()
    key = blind_rsa.derive_fixed_key(shared_key)
    nonce = blind_rsa.encrypt_message_ecb(key, nonce)

    issuer = HeteroAttestationIssuer(ca_cert_path, "test_attest", node_id,
                                     tee_node_addr, nonce, nonce_no_crypto)
    if not issuer.IssueHeteroAttestation():
        logging.error(f"The tee env in {tee_node_addr} is not trusted.")
    else:
        logging.info(f"The tee env in {tee_node_addr} is trusted.")
