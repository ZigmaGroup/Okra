from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from hetero_attestation_pb2_grpc import TeeNodeService
import logging
from datetime import datetime, timedelta
import cryptography.hazmat.backends as backends
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
import hetero_attestation_pb2_grpc
from hetero_attestation_pb2_grpc import TargetInfoService
from hetero_attestation_pb2 import RunStatus
from hetero_attestation_pb2 import TargetInfoResponse
from hetero_attestation_pb2 import TargetInfoRequest
from hetero_attestation_pb2 import TeeAttestationResponse
from hetero_attestation_pb2 import TeeAttestationRequest
from hetero_attestation_pb2 import HeteroAttestationResponse
from hetero_attestation_pb2 import HeteroAttestationRequest
from hetero_attestation_pb2 import RegisterNodeResponse
from hetero_attestation_pb2 import RegisterNodeRequest
from concurrent.futures import ThreadPoolExecutor
import argparse
import hashlib
import json
import grpc
import sys
import os
import key_exchange_pb2
import key_exchange_pb2_grpc
import time

# autopep8: off
sys.path.append("../wrapper/sgx")
import sgx_wrap
# autopep8: on

logging.basicConfig(level=logging.DEBUG,
                    format="[%(asctime)s][%(name)s][%(levelname)s] %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a')
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

class RegisterResult:
    def __init__(self, priv_key, pub_key, node_cert, ca_cert):
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.node_cert = node_cert
        self.ca_cert = ca_cert


def register_sgx_node(node_id, common_name, org_name, center_service_addr):
    # Generate RSA key and CSR.
    enclave_path = "../wrapper/sgx/enclave.signed.so"
    enclave_id = sgx_wrap.init_enclave(enclave_path, True)
    priv_key, pub_key, csr_content = sgx_wrap.gen_then_export_key_and_csr(
        enclave_id, common_name, org_name)
    sgx_wrap.fini_enclave(enclave_id)

    logging.info(
        f"Generate RSA key and CSR for {node_id} from sgx enclave finish.")

    # Reqeust to generate certificate.
    channel = grpc.insecure_channel(center_service_addr)
    stub = hetero_attestation_pb2_grpc.CenterServiceStub(channel)

    # 记录注册开始时间戳
    start_register_time = int(datetime.now().timestamp() * 1000)
    logging.info(f"发送注册请求时间： {start_register_time}")

    request = RegisterNodeRequest(node_id=node_id, csr_content=csr_content)
    response = stub.RegisterNode(request)

    # 记录收到注册响应时间戳
    end_register_time = int(datetime.now().timestamp() * 1000)
    logging.info(f"接收注册响应时间： {end_register_time}")

    # 记录注册请求、注册响应数据量
    register_request_size = len(request.SerializeToString())
    register_response_size = len(response.SerializeToString())
    logging.info(f"注册请求数据量: {register_request_size} bytes")
    logging.info(f"注册响应数据量: {register_response_size} bytes")

    # 记录注册耗时
    register_duration = end_register_time - start_register_time
    logging.info(f"注册阶段总耗时： {register_duration} ms")

    logging.info(
        f"Register node to center attestation service {center_service_addr} finish.")

    return RegisterResult(priv_key, pub_key, response.node_cert, response.ca_cert)


class TeeNodeServiceForSGX(TeeNodeService):
    def __init__(self, node_id, priv_key_path, pub_key_path, node_cert_path,
                 ca_cert_path, center_service_addr):
        self.priv_key_path = priv_key_path
        self.pub_key_path = pub_key_path
        self.ca_cert_path = ca_cert_path
        self.node_id = node_id
        self.node_cert_path = node_cert_path
        self.center_addr = center_service_addr

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
        # 记录收到nonce时间戳
        receive_nonce_time = int(datetime.now().timestamp() * 1000)
        logging.info(f"Receive nonce at {receive_nonce_time}")

        # 记录收到nonce数据量
        receive_nonce_size = len(request.SerializeToString())
        logging.info(f"Receive nonce size: {receive_nonce_size} bytes")


        # Reload RSA key to enclave.
        with open(self.priv_key_path, "rb") as f:
            private_key = f.read()

        with open(self.pub_key_path, "rb") as f:
            public_key = f.read().decode("utf-8")

        with open(self.node_cert_path, "rb") as f:
            node_cert = f.read()

        enclave_path = "../wrapper/sgx/enclave.signed.so"
        enclave_id = sgx_wrap.init_enclave(enclave_path, True)
        sgx_wrap.import_key(enclave_id, private_key, public_key)

        logging.info("Reload RSA key to enclave finish.")

        if len(request.attachment) != 0:
            attach_sig = sgx_wrap.gen_sig(enclave_id, request.attachment)
            logging.info("Generate signature of attachment finish.")

        nonce = request.nonce
        if len(request.report) != 0:
            report = request.report
        else:
            logging.warn("Generate report from example enclave.")
            report = sgx_wrap.gen_example_report(
                "../wrapper/sgx/example.signed.so", nonce)

        logging.info(f"Report from application enclave is:{report.hex()}")

        # Generate SGX proof.
        os.environ['SGX_PRIVATE_KEY_FILE'] = self.priv_key_path
        os.environ['SGX_PUBLIC_KEY_FILE'] = self.pub_key_path
        proof, policy = sgx_wrap.gen_proof(enclave_id, report)

        sgx_wrap.fini_enclave(enclave_id)

        logging.info("Generate SGX proof finish.")

        logging.info("Request center attestation service to verify proof.")

        # 记录发送验证请求时间戳
        send_verify_time = int(datetime.now().timestamp() * 1000)
        logging.info(f"Send verify request at {send_verify_time}")

        # Send to center attestation service.
        attest_request = TeeAttestationRequest(
            tee_proof=proof,
            nonce=request.nonce,
            platform="hetero_sgx",
            policy=policy,
            tee_node_id=self.node_id,
            attest_id=request.attest_id,
            challenger_node_id=request.node_id,
            tee_node_cert=node_cert)

        # 记录发送验证请求数据量
        send_verify_size = len(attest_request.SerializeToString())
        logging.info(f"Send verify request size: {send_verify_size} bytes")

        if len(request.attachment) != 0:
            attest_request.attachment = request.attachment
            attest_request.hex_attach_sig = attach_sig.hex()

        channel = grpc.insecure_channel(self.center_addr)
        stub = hetero_attestation_pb2_grpc.CenterServiceStub(channel)

        verify_response = stub.VerifyTeeProof(attest_request)

        # 记录收到中心认证服务验证响应时间戳
        receive_verify_response_time = int(datetime.now().timestamp() * 1000)
        logging.info(f"Receive verify response at {receive_verify_response_time}")

        # 记录收到中心认证服务验证响应数据量
        receive_verify_response_size = len(verify_response.SerializeToString())
        logging.info(f"Receive verify response size: {receive_verify_response_size} bytes")

        if verify_response.status.error:
            response = HeteroAttestationResponse(
                status=RunStatus(error=True, msg=verify_response.status.msg))
            logging.error(
                f"Center attestion service verify failed, {verify_response.status.msg}")
            return response

        logging.info("Center attestation service return verify result.")

        digest_obj = json.loads(verify_response.service_digest)
        signature = bytes.fromhex(digest_obj["signature"])
        
        if len(request.attachment) != 0:
            message = attest_request.tee_proof + \
                verify_response.verify_result + \
                hashlib.sha256(attest_request.attachment).hexdigest() + \
                attest_request.nonce.hex()
        else:
            message = attest_request.tee_proof + \
                verify_response.verify_result + \
                attest_request.nonce.hex()

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

        response = HeteroAttestationResponse(
            verify_result=verify_response.verify_result,
            tee_proof=proof, signature=digest_obj["signature"],
            nonce=request.nonce,
            status=RunStatus(error=False))

        # 记录转发验证响应时间戳
        send_verify_response_time = int(datetime.now().timestamp() * 1000)
        logging.info(f"Send verify response at {send_verify_response_time}")

        # 记录转发验证响应数据量
        send_verify_response_size = len(response.SerializeToString())
        logging.info(f"Send verify response size: {send_verify_response_size} bytes")

        return response


class TargetInfoServiceForSGX(TargetInfoService):
    def GetQETargetInfo(self, request, response):
        logging.info(f"Generate QE target info for {request.name}.")
        target_info = sgx_wrap.get_qe_target_info(request.name)
        response = TargetInfoResponse(qe_target_info=target_info)
        return response


def setup_cmdline_args():
    parser = argparse.ArgumentParser(description='SGX node service.')
    parser.add_argument("--config", required=True, help="Path of config file.")
    return parser


if __name__ == '__main__':
    parser = setup_cmdline_args()
    args = parser.parse_args()

    with open(args.config, "r") as f:
        conf_obj = json.load(f)

    logging.info(conf_obj)

    node_id = conf_obj["node_id"]
    attest_center_info = conf_obj["center_attestation_service"]
    center_key_exchange_info = conf_obj["center_key_exchange_service"]

    # node_id = "sgx_node"
    result = register_sgx_node(conf_obj["node_id"],
                               conf_obj["csr_field"]["common_name"],
                               conf_obj["csr_field"]["organization_name"],
                               conf_obj["center_attestation_service"])

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

    with open(priv_key_path, "wb") as f:
        f.write(result.priv_key)

    with open(pub_key_path, "wb") as f:
        f.write(result.pub_key)

    with open(node_cert_path, "wb") as f:
        f.write(result.node_cert)

    with open(ca_cert_path, "wb") as f:
        f.write(result.ca_cert)

    with open(shared_key_path, "wb") as f:
        f.write(shared_key)

    server = grpc.server(ThreadPoolExecutor(max_workers=10))

    service_impl = TeeNodeServiceForSGX(conf_obj["node_id"], priv_key_path,
                                        pub_key_path, node_cert_path,
                                        ca_cert_path,
                                        conf_obj["center_attestation_service"])
    hetero_attestation_pb2_grpc.add_TeeNodeServiceServicer_to_server(
        service_impl, server)

    service_impl = TargetInfoServiceForSGX()
    hetero_attestation_pb2_grpc.add_TargetInfoServiceServicer_to_server(
        service_impl, server)

    server.add_insecure_port("[::]:" + conf_obj["listen_port"])
    server.start()

    logging.info("The Node service is running.")
    server.wait_for_termination()
