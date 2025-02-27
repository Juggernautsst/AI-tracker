import json
import unittest
from ai_tracer.core import AITracer
from pycry.cryk import SchnorrSystem

class TestAITracer(unittest.TestCase):
    """测试AI-Tracer模型的基本功能"""
    
    def setUp(self):
        self.crypto = SchnorrSystem()
        # 注意：这里使用模拟连接，实际测试中需要替换为有效连接
        self.tracer = AITracer("http://localhost:8545", "/ip4/127.0.0.1/tcp/5001")
        
        # 禁用真实网络连接以便测试
        self.tracer.ipfs = None
        self.tracer.web3 = None
    
    def test_generate_ai_digest(self):
        """测试AI摘要生成"""
        ai_model_data = {
            "name": "测试模型",
            "version": "1.0",
            "parameters_count": 1000,
            "metrics": {"accuracy": 0.95}
        }
        
        digest = self.tracer.generate_ai_digest(ai_model_data)
        self.assertIn("model_hash", digest)
        self.assertIn("timestamp", digest)
        self.assertEqual(digest["model_metadata"]["name"], "测试模型")
    
    # 添加更多测试...

if __name__ == "__main__":
    unittest.main()