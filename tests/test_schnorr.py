import unittest
import random
import hashlib
from pycry.cryk import SchnorrSystem

class TestSchnorrSystem(unittest.TestCase):
    """测试Schnorr签名系统的各项功能"""
    
    def setUp(self):
        """每个测试前运行，初始化测试环境"""
        # 使用预定义的安全参数初始化系统
        self.schnorr = SchnorrSystem()
        
        # 也测试自定义参数
        # 使用小素数方便测试
        self.custom_schnorr = SchnorrSystem(p=23, q=11, g=2)
    
    def test_key_generation(self):
        """测试密钥生成功能"""
        keys = self.schnorr.key_generation()
        
        # 检查密钥是否包含公钥和私钥
        self.assertIn("public_key", keys)
        self.assertIn("private_key", keys)
        
        # 检查私钥范围 1 <= x <= q-1
        self.assertGreaterEqual(keys["private_key"], 1)
        self.assertLess(keys["private_key"], self.schnorr.q)
        
        # 检查公钥计算是否正确: y = g^(-x) mod p
        x = keys["private_key"]
        y = keys["public_key"]
        expected_y = pow(self.schnorr.g, -x % self.schnorr.q, self.schnorr.p)
        self.assertEqual(y, expected_y)
    
    def test_sign_and_verify(self):
        """测试签名和验证功能"""
        keys = self.schnorr.key_generation()
        message = "测试消息"
        
        # 生成签名
        signature = self.schnorr.sign(message, keys["private_key"])
        
        # 检查签名格式
        self.assertIn("e", signature)
        self.assertIn("s", signature)
        
        # 验证签名有效性
        is_valid = self.schnorr.verify(message, signature, keys["public_key"])
        self.assertTrue(is_valid, "签名应该被正确验证")
        
        # 使用不同的消息测试无效签名
        different_message = "不同的测试消息"
        is_valid = self.schnorr.verify(different_message, signature, keys["public_key"])
        self.assertFalse(is_valid, "对不同消息的签名验证应该失败")
        
        # 使用错误的公钥测试无效签名
        other_keys = self.schnorr.key_generation()
        is_valid = self.schnorr.verify(message, signature, other_keys["public_key"])
        self.assertFalse(is_valid, "使用错误公钥的签名验证应该失败")
    
    def test_encrypt_and_decrypt(self):
        """测试加密和解密功能"""
        keys = self.schnorr.key_generation()
        
        # 测试各种不同的消息
        test_messages = [1, 5, 10, self.schnorr.p - 1]
        
        for message in test_messages:
            # 加密消息
            ciphertext = self.schnorr.encrypt(message, keys["public_key"])
            
            # 检查密文格式
            self.assertIn("c1", ciphertext)
            self.assertIn("c2", ciphertext)
            
            # 解密消息
            decrypted = self.schnorr.decrypt(ciphertext, keys["private_key"])
            
            # 验证原始消息和解密后的消息相同
            self.assertEqual(message, decrypted, f"解密后的消息应与原始消息相同: {message}")
    
    def test_re_encryption(self):
        """测试代理重加密功能"""
        # 生成Alice和Bob的密钥对
        alice_keys = self.schnorr.key_generation()
        bob_keys = self.schnorr.key_generation()
        
        # 原始消息
        message = 42
        
        # Alice加密消息
        ciphertext = self.schnorr.encrypt(message, alice_keys["public_key"])
        
        # Alice生成重加密密钥，允许Bob访问她的加密数据
        re_encryption_key = self.schnorr.generate_re_encryption_key(
            alice_keys["private_key"], bob_keys["public_key"]
        )
        
        # 使用重加密密钥对Alice的密文进行重加密
        re_encrypted = self.schnorr.re_encrypt(ciphertext, re_encryption_key)
        
        # Bob解密重加密的数据
        bob_decrypted = self.schnorr.decrypt(re_encrypted, bob_keys["private_key"])
        
        # 验证Bob解密得到的数据与原始消息相同
        self.assertEqual(message, bob_decrypted, "重加密后Bob应能成功解密获得原始消息")
    
    def test_custom_parameters(self):
        """测试自定义参数初始化"""
        keys = self.custom_schnorr.key_generation()
        message = "自定义参数测试"
        
        # 生成签名
        signature = self.custom_schnorr.sign(message, keys["private_key"])
        
        # 验证签名有效性
        is_valid = self.custom_schnorr.verify(message, signature, keys["public_key"])
        self.assertTrue(is_valid, "使用自定义参数的签名应该被正确验证")
    
    def test_hash_function(self):
        """测试哈希函数实现"""
        message = "测试哈希"
        r = 123
        
        # 使用类的内部哈希函数
        hash_value = self.schnorr._hash(message, r)
        
        # 验证哈希值在预期范围内 (0 <= hash_value < q)
        self.assertGreaterEqual(hash_value, 0)
        self.assertLess(hash_value, self.schnorr.q)
        
        # 验证相同输入产生相同输出
        hash_value2 = self.schnorr._hash(message, r)
        self.assertEqual(hash_value, hash_value2, "对相同输入的哈希应该产生相同结果")
        
        # 验证不同输入产生不同输出
        hash_value3 = self.schnorr._hash("不同测试", r)
        self.assertNotEqual(hash_value, hash_value3, "对不同输入的哈希应该产生不同结果")

    def test_edge_cases(self):
        """测试边缘情况"""
        keys = self.schnorr.key_generation()
        
        # 测试空消息
        empty_message = ""
        signature = self.schnorr.sign(empty_message, keys["private_key"])
        is_valid = self.schnorr.verify(empty_message, signature, keys["public_key"])
        self.assertTrue(is_valid, "空消息应该能被正确签名和验证")
        
        # 测试非常大的消息（通过哈希处理）
        large_message = "x" * 10000  # 一个很长的字符串
        signature = self.schnorr.sign(large_message, keys["private_key"])
        is_valid = self.schnorr.verify(large_message, signature, keys["public_key"])
        self.assertTrue(is_valid, "大消息应该能被正确签名和验证")

if __name__ == "__main__":
    unittest.main()