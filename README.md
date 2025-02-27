

AI-tracker/


├── pycry/          # Schnorr签名系统


├── ai_tracer/      # AI-Tracer核心实现


├── contracts/      # 智能合约


├── tests/          # 测试代码


├── examples/       # 示例代码

#AI-Tracker


本项目旨在利用区块链技术实现对人工智能项目的加密存储与审计。


##完整工作流##

1. 初始化与密钥生成


2. AI模型数据收集与摘要生成


3. 对AI摘要进行签名


4. 加密AI摘要


5. 将加密的AI摘要上传到IPFS


6. 将IPFS哈希和签名上传到区块链


7. 验证AI摘要


# AI-Tracer系统流程图

目前已经完成了对ai模型的收集，并且采用schnorr签名技术生成签名ai摘要，采用签名技术的好处是任何获得到ai摘要和公钥的人都可以验证该签名，然后对ai摘要进行PRE，实现对信息的安全传输，用户采用自己的私钥进行解密，从而实现验证过的用户可以获取到数据。
。

```mermaid
flowchart TD
    subgraph 初始化
        A1[初始化系统与密钥生成]
    end

    subgraph AI摘要处理
        B1[收集AI模型数据]
        B2[生成并签名AI摘要]
        B3[加密AI摘要]
        B1 --> B2 --> B3
    end

    subgraph 存储与记录
        C1[IPFS存储]
        C2[区块链记录]
        C1 --> C2
    end

    subgraph 验证与共享
        D1[验证AI摘要]
        D2[代理重加密与安全共享]
    end

    subgraph 智能合约
        E1[记录管理]
        E2[验证与更新]
        E1 <--> E2
    end
    
    A1 --> B1
    B3 --> C1
    C2 --> D1
    C2 --> D2
    
    C2 --> E1
    D1 --> E2
