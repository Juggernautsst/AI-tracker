

AI-tracker/


├── pycry/          # Schnorr签名系统


├── ai_tracer/      # AI-Tracer核心实现


├── contracts/      # 智能合约


├── tests/          # 测试代码


├── examples/       # 示例代码

#AI-Tracker


本项目旨在利用区块链技术实现对人工智能项目的监管与审计。


##完整工作流##

1. 初始化与密钥生成


2. AI模型数据收集与摘要生成


3. 对AI摘要进行签名


4. 加密AI摘要


5. 将加密的AI摘要上传到IPFS


6. 将IPFS哈希和签名上传到区块链


7. 验证AI摘要


# AI-Tracer系统流程图

```mermaid
from web3 import Web3
import json
import time
from pycry.cryk import SchnorrSystem
from ai_tracer.core import AITracer

def run_complete_workflow():
    print("===== AI-Tracer完整工作流测试 =====")
    
    # 1. 连接到以太坊网络
    web3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
    if not web3.is_connected():
        print("无法连接到以太坊节点。请确保Ganache正在运行。")
        return
    
    # 账户设置
    sender_address = web3.eth.accounts[0]
    web3.eth.default_account = sender_address
    
    # 2. 加载合约
    contract_address = "YOUR_DEPLOYED_CONTRACT_ADDRESS"  # 替换为实际的合约地址
    
    with open("build/contracts/AITracerContract.json", "r") as f:
        contract_json = json.load(f)
        contract_abi = contract_json['abi']
    
    # 3. 初始化AITracer
    tracer = AITracer("http://localhost:8545", "/ip4/127.0.0.1/tcp/5001")
    tracer.set_contract(contract_address, contract_abi)
    tracer.web3 = web3  # 使用已连接的Web3实例
    
    # 4. 初始化加密系统
    crypto = SchnorrSystem()
    
    # 5. 生成密钥对
    owner_keys = crypto.key_generation()
    print(f"数据所有者密钥对: {owner_keys}")
    
    # 6. 创建AI模型数据
    ai_model_data = {
        "name": "深度神经网络",
        "version": "2.0",
        "parameters_count": 5000000,
        "metrics": {
            "accuracy": 0.97,
            "precision": 0.96
        },
        "training_data_hash": "0xabcdef1234567890",
        "learning_parameters": {
            "learning_rate": 0.001,
            "batch_size": 64,
            "epochs": 100
        }
    }
    
    print("处理AI模型数据...")
    try:
        # 7. 执行完整处理流程（模拟IPFS交互）
        tracer.ipfs = None  # 使用模拟模式，不实际连接IPFS
        
        # 7.1 生成AI摘要
        ai_digest = tracer.generate_ai_digest(ai_model_data)
        print(f"AI摘要已生成: {json.dumps(ai_digest, indent=2)[:100]}...")
        
        # 7.2 对AI摘要进行签名
        digest_str = json.dumps(ai_digest, sort_keys=True)
        signature = crypto.sign(digest_str, owner_keys["private_key"])
        print(f"签名已创建: {signature}")
        
        # 7.3 将签名和模拟的IPFS哈希上传到区块链
        ipfs_hash = "QmSim" + digest_str[:40].replace(" ", "")
        
        print(f"模拟的IPFS哈希: {ipfs_hash}")
        print("上传到区块链...")
        
        tx_hash = tracer.contract.functions.recordAIDigest(
            ipfs_hash,
            signature["e"],
            signature["s"]
        ).transact({'from': sender_address})
        
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"交易已确认，区块号: {receipt['blockNumber']}")
        
        # 8. 验证记录
        record = tracer.contract.functions.getAIDigestRecord(ipfs_hash).call()
        print("\nAI摘要记录已成功存储在区块链上:")
        print(f"IPFS哈希: {record[0]}")
        print(f"签名参数: E={record[1]}, S={record[2]}")
        print(f"所有者: {record[3]}")
        print(f"时间戳: {record[4]}")
        print(f"是否有效: {record[5]}")
        
        print("\n===== 工作流程测试完成 =====")
        
    except Exception as e:
        print(f"错误: {e}")

if __name__ == "__main__":
    run_complete_workflow()
