import json
import time
import hashlib
import base64
from typing import Dict, List, Any, Tuple
import ipfshttpclient
from web3 import Web3
import coincurve  # 用于Schnorr签名
from ecies import encrypt, decrypt  # 用于椭圆曲线集成加密方案
from umbral.curve import SECP256K1
from umbral import pre, keys, config # Proxy Re-Encryption库
config.set_default_curve(SECP256K1)

class SchnorrSignatureSystem:
    """Schnorr签名系统类，处理密钥生成、签名和验证"""
    
    def generate_key_pair(self) -> Dict[str, str]:
        """生成一个新的密钥对"""
        private_key = coincurve.PrivateKey()
        public_key = private_key.public_key
        
        return {
            "private_key": private_key.secret,
            "public_key": public_key.format()
        }
    
    def sign(self, data: str, private_key_bytes: bytes) -> str:
        """使用私钥对数据进行签名"""
        private_key = coincurve.PrivateKey(private_key_bytes)
        message_hash = hashlib.sha256(data.encode()).digest()
        signature = private_key.sign_schnorr(message_hash)
        return base64.b64encode(signature).decode()
    
    def verify(self, data: str, signature: str, public_key_bytes: bytes) -> bool:
        """验证数据签名的有效性"""
        public_key = coincurve.PublicKey(public_key_bytes)
        message_hash = hashlib.sha256(data.encode()).digest()
        signature_bytes = base64.b64decode(signature)
        return public_key.verify_schnorr(signature_bytes, message_hash)
    
    def encrypt(self, data: str, public_key_bytes: bytes) -> str:
        """使用公钥加密数据"""
        encrypted_data = encrypt(public_key_bytes, data.encode())
        return base64.b64encode(encrypted_data).decode()
    
    def decrypt(self, encrypted_data: str, private_key_bytes: bytes) -> str:
        """使用私钥解密数据"""
        encrypted_bytes = base64.b64decode(encrypted_data)
        decrypted_data = decrypt(private_key_bytes, encrypted_bytes)
        return decrypted_data.decode()
    
    def hash(self, data: str) -> str:
        """计算数据的哈希值"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def derive_public_key(self, private_key_bytes: bytes) -> bytes:
        """从私钥派生公钥"""
        private_key = coincurve.PrivateKey(private_key_bytes)
        return private_key.public_key.format()


class ProxyReEncryption:
    """代理重加密类，实现对加密数据的安全共享"""
    
    def __init__(self):
        """初始化代理重加密类"""
        # 生成umbral密钥
        self.umbral_keys = {}
    
    def setup_keys(self, public_key_bytes: bytes, private_key_bytes: bytes = None):
        """设置umbral密钥"""
        if private_key_bytes:
            # 如果提供了私钥，就使用它来派生umbral私钥
            umbral_private_key = umbral.keys.UmbralPrivateKey.from_bytes(private_key_bytes)
            umbral_public_key = umbral_private_key.get_pubkey()
        else:
            # 否则，只使用公钥
            umbral_public_key = umbral.keys.UmbralPublicKey.from_bytes(public_key_bytes)
        
        pub_key_hex = public_key_bytes.hex()
        self.umbral_keys[pub_key_hex] = {
            'public_key': umbral_public_key
        }
        
        if private_key_bytes:
            self.umbral_keys[pub_key_hex]['private_key'] = umbral_private_key
    
    def generate_re_encryption_key(self, owner_private_key_bytes: bytes, 
                                  recipient_public_key_bytes: bytes) -> str:
        """生成从所有者到接收者的重加密密钥"""
        # 确保已经设置了密钥
        owner_pub_key_hex = self.derive_public_key(owner_private_key_bytes).hex()
        recipient_pub_key_hex = recipient_public_key_bytes.hex()
        
        if owner_pub_key_hex not in self.umbral_keys or 'private_key' not in self.umbral_keys[owner_pub_key_hex]:
            self.setup_keys(self.derive_public_key(owner_private_key_bytes), owner_private_key_bytes)
        
        if recipient_pub_key_hex not in self.umbral_keys:
            self.setup_keys(recipient_public_key_bytes)
        
        # 生成密钥分片（这里简化为一个分片）
        kfrags = umbral.kfrags.generate_kfrags(
            delegating_privkey=self.umbral_keys[owner_pub_key_hex]['private_key'],
            receiving_pubkey=self.umbral_keys[recipient_pub_key_hex]['public_key'],
            threshold=1,
            N=1,
            signer=self.umbral_keys[owner_pub_key_hex]['private_key']
        )
        
        # 序列化kfrags用于存储
        serialized_kfrags = [kfrag.to_bytes() for kfrag in kfrags]
        return base64.b64encode(serialized_kfrags[0]).decode()
    
    def derive_public_key(self, private_key_bytes: bytes) -> bytes:
        """从私钥派生公钥"""
        private_key = coincurve.PrivateKey(private_key_bytes)
        return private_key.public_key.format()
    
    def encrypt_for_proxy(self, data: str, public_key_bytes: bytes) -> Tuple[str, str]:
        """使用公钥加密数据，为代理重加密做准备"""
        pub_key_hex = public_key_bytes.hex()
        if pub_key_hex not in self.umbral_keys:
            self.setup_keys(public_key_bytes)
        
        # 将数据转换为明文胶囊
        plaintext = data.encode()
        umbral_public_key = self.umbral_keys[pub_key_hex]['public_key']
        
        # 加密数据，生成胶囊
        capsule, ciphertext = umbral.pre.encrypt(umbral_public_key, plaintext)
        
        # 序列化胶囊和密文
        serialized_capsule = base64.b64encode(capsule.to_bytes()).decode()
        serialized_ciphertext = base64.b64encode(ciphertext).decode()
        
        return serialized_capsule, serialized_ciphertext
    
    def reencrypt(self, capsule_str: str, kfrag_str: str) -> str:
        """使用重加密密钥重新加密胶囊"""
        # 反序列化胶囊和kfrag
        capsule_bytes = base64.b64decode(capsule_str)
        kfrag_bytes = base64.b64decode(kfrag_str)
        
        capsule = umbral.pre.Capsule.from_bytes(capsule_bytes)
        kfrag = umbral.kfrags.KFrag.from_bytes(kfrag_bytes)
        
        # 使用kfrag重新加密胶囊
        cfrag = umbral.pre.reencrypt(capsule, kfrag)
        
        # 序列化cfrag
        return base64.b64encode(cfrag.to_bytes()).decode()
    
    def decrypt_reencrypted(self, 
                          capsule_str: str, 
                          cfrag_str: str, 
                          ciphertext_str: str, 
                          delegator_pub_key_bytes: bytes,
                          recipient_private_key_bytes: bytes) -> str:
        """使用接收者的私钥解密重加密数据"""
        # 反序列化数据
        capsule_bytes = base64.b64decode(capsule_str)
        cfrag_bytes = base64.b64decode(cfrag_str)
        ciphertext = base64.b64decode(ciphertext_str)
        
        # 获取必要的密钥
        delegator_pub_key_hex = delegator_pub_key_bytes.hex()
        recipient_pub_key_hex = self.derive_public_key(recipient_private_key_bytes).hex()
        
        if delegator_pub_key_hex not in self.umbral_keys:
            self.setup_keys(delegator_pub_key_bytes)
        
        if recipient_pub_key_hex not in self.umbral_keys or 'private_key' not in self.umbral_keys[recipient_pub_key_hex]:
            self.setup_keys(self.derive_public_key(recipient_private_key_bytes), recipient_private_key_bytes)
        
        # 重建capsule和cfrag
        capsule = umbral.pre.Capsule.from_bytes(capsule_bytes)
        cfrag = umbral.pre.CapFrag.from_bytes(cfrag_bytes)
        
        # 验证cfrag并收集
        delegator_pubkey = self.umbral_keys[delegator_pub_key_hex]['public_key']
        cfrags = [cfrag]  # 在实际应用中可能有多个cfrag
        
        # 解密
        cleartext = umbral.pre.decrypt_reencrypted(
            self.umbral_keys[recipient_pub_key_hex]['private_key'],
            delegator_pubkey,
            capsule,
            cfrags,
            ciphertext
        )
        
        return cleartext.decode()


class IPFSClient:
    """IPFS客户端类，处理数据在IPFS网络上的存储和检索"""
    
    def __init__(self, ipfs_api="/ip4/127.0.0.1/tcp/5001"):
        """初始化IPFS客户端"""
        try:
            self.client = ipfshttpclient.connect(ipfs_api)
        except Exception as e:
            print(f"无法连接到IPFS: {e}")
            print("使用模拟IPFS客户端")
            self.client = None
            self.mock_storage = {}
    
    def store(self, data: str) -> str:
        """将数据存储到IPFS并返回哈希"""
        if self.client:
            result = self.client.add_str(data)
            return result
        else:
            # 模拟存储
            hash_value = hashlib.sha256(data.encode()).hexdigest()
            self.mock_storage[hash_value] = data
            return hash_value
    
    def retrieve(self, hash_value: str) -> str:
        """从IPFS检索数据"""
        if self.client:
            return self.client.cat(hash_value).decode()
        else:
            # 模拟检索
            if hash_value in self.mock_storage:
                return self.mock_storage[hash_value]
            else:
                raise Exception(f"找不到哈希为 {hash_value} 的数据")


class SmartBlockchain:
    """智能区块链类，处理区块链上的记录存储和检索"""
    
    def __init__(self, contract_address=None, web3_provider=None):
        """初始化智能区块链客户端"""
        self.using_mock = True
        if web3_provider and contract_address:
            try:
                self.web3 = Web3(Web3.HTTPProvider(web3_provider))
                self.contract_address = contract_address
                # 实际应用中需要加载合约ABI
                self.contract = self.web3.eth.contract(
                    address=contract_address,
                    abi=[] # 这里需要实际的合约ABI
                )
                self.using_mock = False
            except Exception as e:
                print(f"无法连接到区块链: {e}")
                print("使用模拟区块链")
        
        if self.using_mock:
            self.mock_blockchain = {}
            self.transaction_counter = 0
    
    def store_record(self, record: Dict[str, Any]) -> str:
        """将记录存储到区块链"""
        if not self.using_mock:
            # 实际区块链交互
            tx_hash = self.contract.functions.storeAISummary(
                record['ipfs_hash'],
                record['owner_public_key'],
                record['reencryption_key'],
                record['timestamp'],
                record['summary_signature']
            ).transact({'from': self.web3.eth.accounts[0]})
            
            # 等待交易确认
            tx_receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            return tx_receipt.transactionHash.hex()
        else:
            # 模拟存储
            self.transaction_counter += 1
            tx_id = f"tx_{self.transaction_counter}_{int(time.time())}"
            self.mock_blockchain[tx_id] = {
                'record': record,
                'access_controls': []
            }
            return tx_id
    
    def get_record(self, transaction_id: str) -> Dict[str, Any]:
        """从区块链获取记录"""
        if not self.using_mock:
            # 实际区块链交互
            record = self.contract.functions.getAISummary(transaction_id).call()
            return record
        else:
            # 模拟检索
            if transaction_id in self.mock_blockchain:
                return self.mock_blockchain[transaction_id]
            else:
                raise Exception(f"找不到交易ID为 {transaction_id} 的记录")
    
    def update_access_control(self, transaction_id: str, access_control: Dict[str, Any]) -> str:
        """更新记录的访问控制"""
        if not self.using_mock:
            # 实际区块链交互
            tx_hash = self.contract.functions.updateAccessControl(
                transaction_id,
                access_control['user_public_key'],
                access_control['reencryption_key'],
                access_control['access_level'],
                access_control['expiry_time']
            ).transact({'from': self.web3.eth.accounts[0]})
            
            # 等待交易确认
            tx_receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            return tx_receipt.transactionHash.hex()
        else:
            # 模拟更新
            if transaction_id in self.mock_blockchain:
                self.mock_blockchain[transaction_id]['access_controls'].append(access_control)
                return f"access_update_{int(time.time())}"
            else:
                raise Exception(f"找不到交易ID为 {transaction_id} 的记录")


class AITracer:
    """AI-Tracer主类，协调所有组件以实现AI行为追踪"""
    
    def __init__(self, ipfs_api=None, web3_provider=None, contract_address=None):
        """初始化AI-Tracer系统"""
        self.ipfs = IPFSClient(ipfs_api if ipfs_api else "/ip4/127.0.0.1/tcp/5001")
        self.blockchain = SmartBlockchain(contract_address, web3_provider)
        self.schnorr_crypto = SchnorrSignatureSystem()
        self.proxy_reencryption = ProxyReEncryption()
    
    def generate_ai_summary(self, ai_model: Any, learning_session: Any) -> Dict[str, Any]:
        """在AI学习过程中生成摘要"""
        # 从AI模型和学习会话中提取信息
        # 实际应用中，这将与特定的AI框架集成
        
        # 模拟提取AI模型指标
        ai_metrics = {
            "accuracy": 0.95,
            "loss": 0.05,
            "epochs_completed": 100,
            "training_time": 3600
        }
        
        # 模拟模型参数
        model_parameters = {
            "layer_1": {"weights": [0.1, 0.2, 0.3], "biases": [0.01, 0.02]},
            "layer_2": {"weights": [0.4, 0.5, 0.6], "biases": [0.03, 0.04]}
        }
        
        # 模拟数据引用
        data_used = {
            "dataset_id": "dataset_123",
            "samples_count": 10000,
            "data_hash": "sha256:1234567890abcdef"
        }
        
        # 构建AI摘要
        ai_summary = {
            "model_id": "model_" + self.schnorr_crypto.hash(str(time.time())),
            "timestamp": int(time.time()),
            "metrics": ai_metrics,
            "parameter_hashes": self._hash_parameters(model_parameters),
            "data_references": data_used,
            "learning_type": "supervised"
        }
        
        return ai_summary
    
    def encrypt_and_store_ai_summary(self, ai_summary: Dict[str, Any], owner_public_key: bytes) -> Dict[str, str]:
        """对AI摘要进行加密并存储"""
        # 生成加密密钥对
        encryption_keys = self.schnorr_crypto.generate_key_pair()
        encryption_private_key = encryption_keys["private_key"]
        encryption_public_key = encryption_keys["public_key"]
        
        # 将AI摘要转换为JSON字符串
        ai_summary_json = json.dumps(ai_summary)
        
        # 对摘要进行签名
        summary_signature = self.schnorr_crypto.sign(ai_summary_json, encryption_private_key)
        
        # 准备代理重加密
        self.proxy_reencryption.setup_keys(encryption_public_key, encryption_private_key)
        
        # 使用代理重加密系统加密AI摘要
        capsule, ciphertext = self.proxy_reencryption.encrypt_for_proxy(ai_summary_json, encryption_public_key)
        
        # 生成所有者的重加密密钥
        reencryption_key = self.proxy_reencryption.generate_re_encryption_key(
            encryption_private_key,
            owner_public_key
        )
        
        # 将加密数据组合为一个JSON对象
        encrypted_data = json.dumps({
            "capsule": capsule,
            "ciphertext": ciphertext,
            "delegator_public_key": encryption_public_key.hex()
        })
        
        # 存储加密的摘要到IPFS
        ipfs_hash = self.ipfs.store(encrypted_data)
        
        # 准备区块链存储记录
        blockchain_record = {
            "ipfs_hash": ipfs_hash,
            "owner_public_key": owner_public_key.hex(),
            "reencryption_key": reencryption_key,
            "timestamp": int(time.time()),
            "summary_signature": summary_signature
        }
        
        # 将记录存储到区块链
        transaction_id = self.blockchain.store_record(blockchain_record)
        
        return {
            "transaction_id": transaction_id,
            "ipfs_hash": ipfs_hash
        }
    
    def verify_ai_summary(self, ipfs_hash: str, signature: str, public_key: bytes) -> bool:
        """验证AI摘要的有效性"""
        # 从IPFS获取加密的摘要
        encrypted_data_json = self.ipfs.retrieve(ipfs_hash)
        encrypted_data = json.loads(encrypted_data_json)
        
        # 验证摘要的签名
        # 注意：在实际应用中，这需要解密数据才能验证
        # 这里我们假设签名是针对加密数据的
        return self.schnorr_crypto.verify(
            encrypted_data_json,
            signature,
            public_key
        )
    
    def authorize_access(self, transaction_id: str, user_public_key: bytes, owner_private_key: bytes) -> bool:
        """授权用户访问AI摘要"""
        # 从区块链获取记录
        record = self.blockchain.get_record(transaction_id)
        
        # 提取所有者的公钥
        owner_public_key = bytes.fromhex(record['record']['owner_public_key'])
        
        # 验证请求者确实是所有者
        derived_public_key = self.schnorr_crypto.derive_public_key(owner_private_key)
        if derived_public_key != owner_public_key:
            raise Exception("授权失败：私钥与记录所有者不匹配")
        
        # 从IPFS获取加密数据
        encrypted_data_json = self.ipfs.retrieve(record['record']['ipfs_hash'])
        encrypted_data = json.loads(encrypted_data_json)
        
        # 获取委托者的公钥
        delegator_public_key = bytes.fromhex(encrypted_data['delegator_public_key'])
        
        # 设置代理重加密密钥
        self.proxy_reencryption.setup_keys(owner_public_key, owner_private_key)
        self.proxy_reencryption.setup_keys(delegator_public_key)
        self.proxy_reencryption.setup_keys(user_public_key)
        
        # 生成用户特定的重加密密钥
        user_reencryption_key = self.proxy_reencryption.generate_re_encryption_key(
            owner_private_key,
            user_public_key
        )
        
        # 更新区块链上的授权信息
        access_control = {
            "user_public_key": user_public_key.hex(),
            "reencryption_key": user_reencryption_key,
            "access_level": "read",
            "expiry_time": int(time.time()) + (30 * 24 * 60 * 60)  # 30天访问权限
        }
        
        self.blockchain.update_access_control(transaction_id, access_control)
        
        return True
    
    def access_ai_summary(self, transaction_id: str, user_private_key: bytes) -> Dict[str, Any]:
        """授权用户访问AI摘要明文"""
        # 从区块链获取记录
        record = self.blockchain.get_record(transaction_id)
        
        # 派生用户公钥
        user_public_key = self.schnorr_crypto.derive_public_key(user_private_key)
        user_public_key_hex = user_public_key.hex()
        
        # 验证用户是否有访问权限
        access_found = False
        access_control = None
        
        for ac in record['access_controls']:
            if ac['user_public_key'] == user_public_key_hex:
                access_found = True
                access_control = ac
                break
        
        if not access_found or access_control['expiry_time'] < time.time():
            raise Exception("无访问权限或权限已过期")
        
        # 从IPFS获取加密的摘要
        encrypted_data_json = self.ipfs.retrieve(record['record']['ipfs_hash'])
        encrypted_data = json.loads(encrypted_data_json)
        
        # 提取必要的数据
        capsule = encrypted_data['capsule']
        ciphertext = encrypted_data['ciphertext']
        delegator_public_key = bytes.fromhex(encrypted_data['delegator_public_key'])
        
        # 设置代理重加密密钥
        self.proxy_reencryption.setup_keys(delegator_public_key)
        self.proxy_reencryption.setup_keys(user_public_key, user_private_key)
        
        # 重加密capsule
        cfrag = self.proxy_reencryption.reencrypt(capsule, access_control['reencryption_key'])
        
        # 解密数据
        decrypted_json = self.proxy_reencryption.decrypt_reencrypted(
            capsule,
            cfrag,
            ciphertext,
            delegator_public_key,
            user_private_key
        )
        
        # 解析JSON
        return json.loads(decrypted_json)
    
    def _hash_parameters(self, parameters: Dict[str, Any]) -> Dict[str, str]:
        """对模型参数进行哈希处理"""
        hashed_params = {}
        for key, value in parameters.items():
            hashed_params[key] = self.schnorr_crypto.hash(json.dumps(value))
        return hashed_params


# 使用示例
def demo_ai_tracer():
    """演示AI-Tracer的使用"""
    print("初始化AI-Tracer...")
    ai_tracer = AITracer()
    
    print("\n生成密钥对...")
    # 生成所有者的密钥对
    owner_keys = ai_tracer.schnorr_crypto.generate_key_pair()
    owner_private_key = owner_keys["private_key"]
    owner_public_key = owner_keys["public_key"]
    
    print(f"所有者公钥: {owner_public_key.hex()[:10]}...")
    
    print("\n步骤1: 生成AI摘要")
    # 模拟AI模型和学习会话
    ai_model = {"name": "SimpleNN", "version": "1.0"}
    learning_session = {"id": "session_123", "type": "supervised"}
    
    ai_summary = ai_tracer.generate_ai_summary(ai_model, learning_session)
    print(f"AI摘要已生成: {json.dumps(ai_summary, indent=2)[:100]}...")
    
    print("\n步骤2: 加密并存储AI摘要")
    store_result = ai_tracer.encrypt_and_store_ai_summary(ai_summary, owner_public_key)
    print(f"AI摘要已加密并存储，事务ID: {store_result['transaction_id']}")
    print(f"IPFS哈希: {store_result['ipfs_hash']}")
    
    print("\n步骤3: 授权用户访问")
    # 生成用户的密钥对
    user_keys = ai_tracer.schnorr_crypto.generate_key_pair()
    user_private_key = user_keys["private_key"]
    user_public_key = user_keys["public_key"]
    
    print(f"用户公钥: {user_public_key.hex()[:10]}...")
    
    ai_tracer.authorize_access(store_result['transaction_id'], user_public_key, owner_private_key)
    print("用户已授权访问AI摘要")
    
    print("\n步骤4: 用户访问AI摘要明文")
    try:
        decrypted_summary = ai_tracer.access_ai_summary(store_result['transaction_id'], user_private_key)
        print(f"解密的AI摘要: {json.dumps(decrypted_summary, indent=2)}")
        print("演示完成!")
    except Exception as e:
        print(f"访问失败: {e}")


if __name__ == "__main__":
    demo_ai_tracer()