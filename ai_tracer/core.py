import hashlib
import json
import time
from typing import Dict, Any, Optional, List, Tuple
import ipfshttpclient
from web3 import Web3

# 导入已有的Schnorr签名系统
from pycry.cryk import SchnorrSystem

class AITracer:
    """
    AI-Tracer模型：利用基于Schnorr签名的代理重加密和IPFS，
    实现AI行为的可信追踪和验证
    """
    
    def __init__(self, blockchain_url: str, ipfs_api: str = "/ip4/127.0.0.1/tcp/5001"):
        """
        初始化AI-Tracer
        
        参数:
            blockchain_url: 区块链节点URL
            ipfs_api: IPFS API地址
        """
        # 初始化加密系统
        self.crypto = SchnorrSystem()
        
        # 初始化IPFS客户端
        try:
            self.ipfs = ipfshttpclient.connect(ipfs_api)
        except Exception as e:
            print(f"IPFS连接失败: {e}")
            self.ipfs = None
            
        # 初始化区块链连接
        try:
            self.web3 = Web3(Web3.HTTPProvider(blockchain_url))
            if not self.web3.isConnected():
                print("区块链连接失败")
                self.web3 = None
        except Exception as e:
            print(f"区块链连接失败: {e}")
            self.web3 = None
            
        # 智能合约配置 - 实际应用中需要替换为真实的合约地址和ABI
        self.contract_address = None
        self.contract_abi = None
        self.contract = None
    
    def set_contract(self, address: str, abi: List[Dict[str, Any]]):
        """
        设置智能合约
        
        参数:
            address: 合约地址
            abi: 合约ABI
        """
        if self.web3 is not None:
            self.contract_address = address
            self.contract_abi = abi
            self.contract = self.web3.eth.contract(address=address, abi=abi)
    
    def generate_ai_digest(self, ai_model_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        生成AI摘要数据
        
        参数:
            ai_model_data: AI模型数据
            
        返回:
            AI摘要数据
        """
        # 生成时间戳
        timestamp = int(time.time())
        
        # 计算模型数据哈希
        model_hash = hashlib.sha256(json.dumps(ai_model_data, sort_keys=True).encode()).hexdigest()
        
        # 构造AI摘要
        ai_digest = {
            "model_hash": model_hash,
            "timestamp": timestamp,
            "model_metadata": {
                "name": ai_model_data.get("name", "Unknown"),
                "version": ai_model_data.get("version", "1.0"),
                "accuracy": ai_model_data.get("metrics", {}).get("accuracy", 0),
                "parameters_count": ai_model_data.get("parameters_count", 0)
            },
            "training_data_hash": ai_model_data.get("training_data_hash", ""),
            "learning_parameters": ai_model_data.get("learning_parameters", {})
        }
        
        return ai_digest
    
    def encrypt_ai_digest(self, ai_digest: Dict[str, Any], owner_keys: Dict[str, int]) -> Dict[str, Any]:
        """
        加密AI摘要
        
        参数:
            ai_digest: AI摘要数据
            owner_keys: 数据所有者的密钥对
            
        返回:
            加密的AI摘要
        """
        # 将AI摘要转换为字符串
        digest_str = json.dumps(ai_digest, sort_keys=True)
        
        # 由于Schnorr加密需要整数输入，我们将字符串转换为整数列表
        digest_bytes = digest_str.encode('utf-8')
        encrypted_chunks = []
        
        # 分块加密（每次处理一个整数）
        for byte in digest_bytes:
            encrypted_chunk = self.crypto.encrypt(int(byte), owner_keys["public_key"])
            encrypted_chunks.append(encrypted_chunk)
        
        return {
            "encrypted_chunks": encrypted_chunks,
            "digest_length": len(digest_bytes)
        }
    
    def decrypt_ai_digest(self, encrypted_digest: Dict[str, Any], private_key: int) -> Dict[str, Any]:
        """
        解密AI摘要
        
        参数:
            encrypted_digest: 加密的AI摘要
            private_key: 接收者的私钥
            
        返回:
            解密后的AI摘要
        """
        encrypted_chunks = encrypted_digest["encrypted_chunks"]
        digest_length = encrypted_digest["digest_length"]
        
        # 解密每个块
        decrypted_bytes = bytearray()
        for chunk in encrypted_chunks:
            byte_val = self.crypto.decrypt(chunk, private_key)
            decrypted_bytes.append(byte_val)
        
        # 将字节转换回原始格式
        digest_str = decrypted_bytes.decode('utf-8')
        return json.loads(digest_str)
    
    def generate_re_encryption_key(self, owner_private_key: int, recipient_public_key: int) -> int:
        """
        生成重加密密钥
        
        参数:
            owner_private_key: 数据所有者的私钥
            recipient_public_key: 数据接收者的公钥
            
        返回:
            重加密密钥
        """
        return self.crypto.generate_re_encryption_key(owner_private_key, recipient_public_key)
    
    def re_encrypt_ai_digest(self, encrypted_digest: Dict[str, Any], re_encryption_key: int) -> Dict[str, Any]:
        """
        重加密AI摘要
        
        参数:
            encrypted_digest: 已加密的AI摘要
            re_encryption_key: 重加密密钥
            
        返回:
            重加密后的AI摘要
        """
        encrypted_chunks = encrypted_digest["encrypted_chunks"]
        re_encrypted_chunks = []
        
        # 对每个加密块进行重加密
        for chunk in encrypted_chunks:
            re_encrypted_chunk = self.crypto.re_encrypt(chunk, re_encryption_key)
            re_encrypted_chunks.append(re_encrypted_chunk)
        
        return {
            "encrypted_chunks": re_encrypted_chunks,
            "digest_length": encrypted_digest["digest_length"]
        }
    
    def upload_to_ipfs(self, data: Dict[str, Any]) -> str:
        """
        将数据上传到IPFS
        
        参数:
            data: 要上传的数据
            
        返回:
            IPFS哈希指针
        """
        if self.ipfs is None:
            raise RuntimeError("IPFS客户端未连接")
        
        # 将数据转换为JSON字符串
        data_json = json.dumps(data)
        
        # 上传到IPFS
        res = self.ipfs.add_str(data_json)
        return res  # 返回IPFS哈希
    
    def retrieve_from_ipfs(self, ipfs_hash: str) -> Dict[str, Any]:
        """
        从IPFS检索数据
        
        参数:
            ipfs_hash: IPFS哈希指针
            
        返回:
            检索到的数据
        """
        if self.ipfs is None:
            raise RuntimeError("IPFS客户端未连接")
        
        # 从IPFS获取数据
        data_json = self.ipfs.cat(ipfs_hash).decode('utf-8')
        return json.loads(data_json)
    
    def verify_ai_digest(self, ai_digest: Dict[str, Any], signature: Dict[str, int], public_key: int) -> bool:
        """
        验证AI摘要的有效性
        
        参数:
            ai_digest: AI摘要
            signature: 摘要签名
            public_key: 验证签名的公钥
            
        返回:
            验证结果
        """
        # 将AI摘要转换为字符串进行签名验证
        digest_str = json.dumps(ai_digest, sort_keys=True)
        return self.crypto.verify(digest_str, signature, public_key)
    
    def upload_to_blockchain(self, sender_address: str, ipfs_hash: str, signature: Dict[str, int]) -> str:
        """
        将IPFS哈希和签名上传到区块链
        
        参数:
            sender_address: 发送者的区块链地址
            ipfs_hash: IPFS哈希指针
            signature: AI摘要的签名
            
        返回:
            交易哈希
        """
        if self.web3 is None or self.contract is None:
            raise RuntimeError("区块链或智能合约未配置")
        
        # 将签名转换为适合智能合约的格式
        sig_e = signature["e"]
        sig_s = signature["s"]
        
        # 构建交易
        txn = self.contract.functions.recordAIDigest(
            ipfs_hash,
            sig_e,
            sig_s
        ).buildTransaction({
            'from': sender_address,
            'nonce': self.web3.eth.getTransactionCount(sender_address),
            'gas': 2000000,
            'gasPrice': self.web3.toWei('50', 'gwei')
        })
        
        # 需要用户私钥签名交易
        # 注意：这里只返回交易对象，实际应用中需要用户签名后发送
        return txn
    
    def process_ai_model(self, ai_model_data: Dict[str, Any], owner_keys: Dict[str, int], sender_address: str) -> Dict[str, Any]:
        """
        处理AI模型数据的完整工作流
        
        参数:
            ai_model_data: AI模型数据
            owner_keys: 数据所有者的密钥对
            sender_address: 发送者的区块链地址
            
        返回:
            处理结果
        """
        # 1. 生成AI摘要
        ai_digest = self.generate_ai_digest(ai_model_data)
        
        # 2. 对AI摘要进行签名
        digest_str = json.dumps(ai_digest, sort_keys=True)
        signature = self.crypto.sign(digest_str, owner_keys["private_key"])
        
        # 3. 加密AI摘要
        encrypted_digest = self.encrypt_ai_digest(ai_digest, owner_keys)
        
        # 4. 将加密的AI摘要上传到IPFS
        ipfs_hash = self.upload_to_ipfs(encrypted_digest)
        
        # 5. 将IPFS哈希和签名上传到区块链
        txn = self.upload_to_blockchain(sender_address, ipfs_hash, signature)
        
        return {
            "ai_digest": ai_digest,
            "signature": signature,
            "ipfs_hash": ipfs_hash,
            "blockchain_transaction": txn
        }