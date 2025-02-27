from web3 import Web3
import json
import os
import solcx

def main():
    """部署AI-Tracer智能合约"""
    print("准备部署AI-Tracer智能合约...")
    
    # 连接到以太坊节点
    web3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
    
    if not web3.isConnected():
        print("无法连接到以太坊节点。请确保节点正在运行。")
        return
    
    print("连接成功！")
    
    # 设置部署账户
    deployer_address = web3.eth.accounts[0]  # 使用第一个账户作为部署者
    print(f"使用账户 {deployer_address} 部署合约")
    
    # 编译智能合约
    print("编译智能合约...")
    contract_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                              "contracts", "AITracerContract.sol")
    
    try:
        # 确保已安装solc编译器
        try:
            solcx.install_solc('0.8.0')
        except Exception:
            pass  # 如果已安装则忽略
            
        compiled_sol = solcx.compile_files(
            [contract_path], 
            output_values=["abi", "bin"],
            solc_version="0.8.0"
        )
        
        contract_id = f"{contract_path}:AITracerContract"
        contract_interface = compiled_sol[contract_id]
        
        # 获取合约字节码和ABI
        bytecode = contract_interface['bin']
        abi = contract_interface['abi']
        
        # 保存ABI到文件
        with open('contract_abi.json', 'w') as f:
            json.dump(abi, f)
            
        print("合约编译成功，ABI已保存到contract_abi.json")
        
        # 部署合约
        print("部署合约...")
        AITracerContract = web3.eth.contract(abi=abi, bytecode=bytecode)
        
        # 构建交易
        tx_hash = AITracerContract.constructor().transact({
            'from': deployer_address,
            'gas': 3000000
        })
        
        # 等待交易被挖矿确认
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        contract_address = tx_receipt['contractAddress']
        
        print(f"合约部署成功，地址: {contract_address}")
        print(f"保存合约地址以便后续使用")
        
        # 保存合约地址
        with open('contract_address.txt', 'w') as f:
            f.write(contract_address)
            
    except Exception as e:
        print(f"部署失败: {e}")

if __name__ == "__main__":
    main()