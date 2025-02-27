import hashlib
import random
from typing import Tuple, Dict, Any, Optional

class SchnorrSystem:
    """
    Schnorr签名系统类，提供密钥生成、签名、验证以及代理重加密功能
    """
    
    def __init__(self, p: int = None, q: int = None, g: int = None):
        """
        初始化Schnorr签名系统
        
        参数:
            p: 大素数
            q: p-1的素因子
            g: 阶为q的生成元
        """
        if p is None or q is None or g is None:
            # 使用预定义的安全参数，实际应用中应使用更大的参数
            self.p = 23  # 大素数
            self.q = 11  # p-1的一个素因子
            self.g = 2   # 阶为q的生成元
        else:
            self.p = p
            self.q = q
            self.g = g
    
    def key_generation(self) -> Dict[str, int]:
        """
        生成Schnorr签名密钥对
        
        返回:
            包含公钥和私钥的字典
        """
        # 选择私钥 x, 1 <= x <= q-1
        x = random.randint(1, self.q - 1)
        
        # 计算公钥 y = g^(-x) mod p
        y = pow(self.g, -x % self.q, self.p)
        
        return {
            "public_key": y,
            "private_key": x
        }
    
    def _hash(self, message: str, r: int) -> int:
        """
        计算消息和r的哈希值
        
        参数:
            message: 要签名的消息
            r: 签名过程中的随机数承诺
            
        返回:
            整数形式的哈希值，范围在1到q-1之间
        """
        h = hashlib.sha256()
        h.update(f"{message}{r}".encode())
        # 将哈希值转换为整数并取模q
        return int(h.hexdigest(), 16) % self.q
    
    def sign(self, message: str, private_key: int) -> Dict[str, int]:
        """
        使用Schnorr算法对消息进行签名
        
        参数:
            message: 要签名的消息
            private_key: 私钥
            
        返回:
            包含签名参数的字典
        """
        # 生成随机数k，1 <= k <= q-1
        k = random.randint(1, self.q - 1)
        
        # 计算r = g^k mod p
        r = pow(self.g, k, self.p)
        
        # 计算哈希值e
        e = self._hash(message, r)
        
        # 计算s = k + x*e mod q
        s = (k + private_key * e) % self.q
        
        return {
            "e": e,
            "s": s
        }
    
    def verify(self, message: str, signature: Dict[str, int], public_key: int) -> bool:
        """
        验证Schnorr签名
        
        参数:
            message: 签名的消息
            signature: 签名参数
            public_key: 验证签名的公钥
            
        返回:
            如果签名有效则返回True，否则返回False
        """
        e = signature["e"]
        s = signature["s"]
        
        # 计算r' = g^s * y^e mod p
        r_prime = (pow(self.g, s, self.p) * pow(public_key, e, self.p)) % self.p
        
        # 重新计算哈希值e'
        e_prime = self._hash(message, r_prime)
        
        # 验证e是否等于e'
        return e == e_prime
    
    def encrypt(self, message: int, public_key: int) -> Dict[str, int]:
        """
        使用公钥加密消息
        
        参数:
            message: 要加密的消息（整数形式）
            public_key: 接收者的公钥
            
        返回:
            加密的消息
        """
        # 生成随机数k，1 <= k <= q-1
        k = random.randint(1, self.q - 1)
        
        # 计算一次性密钥对
        c1 = pow(self.g, k, self.p)
        
        # 使用共享密钥加密消息
        shared_key = pow(public_key, k, self.p)
        c2 = (message * shared_key) % self.p
        
        return {
            "c1": c1,
            "c2": c2
        }
    
    def decrypt(self, ciphertext: Dict[str, int], private_key: int) -> int:
        """
        使用私钥解密消息
        
        参数:
            ciphertext: 加密的消息
            private_key: 接收者的私钥
            
        返回:
            解密后的明文消息
        """
        c1 = ciphertext["c1"]
        c2 = ciphertext["c2"]
        
        # 恢复共享密钥
        shared_key = pow(c1, private_key, self.p)
        
        # 计算共享密钥的乘法逆元
        shared_key_inv = pow(shared_key, -1, self.p)
        
        # 解密消息
        message = (c2 * shared_key_inv) % self.p
        
        return message
    
    def generate_re_encryption_key(self, sender_private_key: int, recipient_public_key: int) -> int:
        """
        生成重加密密钥
        
        参数:
            sender_private_key: 数据所有者的私钥
            recipient_public_key: 数据接收者的公钥
            
        返回:
            重加密密钥
        """
        # 重加密密钥是从发送者私钥到接收者公钥的转换
        # 计算方式: rk = recipient_public_key^sender_private_key mod p
        re_encryption_key = pow(recipient_public_key, sender_private_key, self.p)
        
        return re_encryption_key
    
    def re_encrypt(self, ciphertext: Dict[str, int], re_encryption_key: int) -> Dict[str, int]:
        """
        使用重加密密钥重新加密密文
        
        参数:
            ciphertext: 原始加密数据
            re_encryption_key: 重加密密钥
            
        返回:
            重新加密的密文
        """
        c1 = ciphertext["c1"]
        c2 = ciphertext["c2"]
        
        # 使用重加密密钥修改c1
        c1_prime = (c1 * re_encryption_key) % self.p
        
        return {
            "c1": c1_prime,
            "c2": c2
        }


def test_schnorr_system():
    """测试Schnorr签名系统的各个功能"""
    # 创建签名系统实例
    schnorr = SchnorrSystem()
    
    # 测试密钥生成
    alice_keys = schnorr.key_generation()
    print(f"Alice的密钥对: {alice_keys}")
    
    # 测试签名和验证
    message = "Hello, Schnorr!"
    signature = schnorr.sign(message, alice_keys["private_key"])
    is_valid = schnorr.verify(message, signature, alice_keys["public_key"])
    print(f"签名验证结果: {is_valid}")
    
    # 测试加密和解密
    plaintext = 42
    ciphertext = schnorr.encrypt(plaintext, alice_keys["public_key"])
    decrypted = schnorr.decrypt(ciphertext, alice_keys["private_key"])
    print(f"原始消息: {plaintext}, 解密后: {decrypted}")
    
    # 测试代理重加密
    bob_keys = schnorr.key_generation()
    print(f"Bob的密钥对: {bob_keys}")
    
    # Alice生成重加密密钥，允许Bob访问她的加密数据
    re_encryption_key = schnorr.generate_re_encryption_key(
        alice_keys["private_key"], bob_keys["public_key"]
    )
    
    # 对Alice的密文进行重加密
    re_encrypted = schnorr.re_encrypt(ciphertext, re_encryption_key)
    
    # Bob解密重加密的数据
    bob_decrypted = schnorr.decrypt(re_encrypted, bob_keys["private_key"])
    print(f"Bob解密结果: {bob_decrypted}")


if __name__ == "__main__":
    test_schnorr_system()