import json
import os
from ai_tracer.core import AITracer
from pycry.cryk import SchnorrSystem

def main():
    """AI-Tracer示例运行程序"""
    print("初始化AI-Tracer模型...")
    
    # 初始化加密系统
    crypto = SchnorrSystem()
    
    # 初始化AI-Tracer
    # 实际使用时替换为真实的区块链和IPFS节点地址
    tracer = AITracer("http://localhost:8545", "/ip4/127.0.0.1/tcp/5001")
    
    # 生成示例AI模型数据
    ai_model_data = {
        "name": "深度学习模型",
        "version": "1.0",
        "parameters_count": 10000000,
        "metrics": {
            "accuracy": 0.95,
            "precision": 0.94,
            "recall": 0.93
        },
        "training_data_hash": "0x1234567890abcdef",
        "learning_parameters": {
            "learning_rate": 0.001,
            "batch_size": 32,
            "epochs": 100,
            "optimizer": "Adam"
        }
    }
    
    # 生成密钥对
    owner_keys = crypto.key_generation()
    print(f"数据所有者密钥对: {owner_keys}")
    
    # 处理AI模型
    try:
        # 此处仅模拟处理，不实际连接区块链和IPFS
        # 如需完整演示，请确保区块链和IPFS节点已正确配置
        print("生成AI摘要...")
        ai_digest = tracer.generate_ai_digest(ai_model_data)
        print(f"AI摘要示例:\n{json.dumps(ai_digest, indent=2)}")
        
        print("\nAI-Tracer示例运行完成！")
    except Exception as e:
        print(f"错误: {e}")

if __name__ == "__main__":
    main()