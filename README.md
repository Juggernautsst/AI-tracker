

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
flowchart TD
    subgraph 初始化与准备
        A1[初始化Schnorr签名系统]
        A2[初始化AI-Tracer]
        A3[生成数据所有者密钥对]
        A1 --> A2 --> A3
    end

    subgraph AI摘要生成与加密
        B1[收集AI模型数据]
        B2[生成AI摘要]
        B3[对AI摘要进行签名]
        B4[加密AI摘要]
        B1 --> B2 --> B3 --> B4
    end

    subgraph 分布式存储
        C1[将加密摘要上传到IPFS]
        C2[获取IPFS哈希指针]
        C1 --> C2
    end

    subgraph 区块链记录
        D1[准备区块链交易]
        D2[调用智能合约recordAIDigest]
        D3[区块链记录AI摘要信息]
        D4[触发AIDigestRecorded事件]
        D1 --> D2 --> D3 --> D4
    end

    subgraph 验证流程
        E1[从区块链获取记录]
        E2[从IPFS获取加密摘要]
        E3[验证签名]
        E4[验证记录完整性]
        E1 --> E3
        E2 --> E3
        E3 --> E4
    end

    subgraph 安全共享流程
        F1[生成接收者密钥对]
        F2[生成代理重加密密钥]
        F3[重加密AI摘要]
        F4[接收者解密]
        F1 --> F2 --> F3 --> F4
    end

    subgraph 管理与更新
        G1[查询AI摘要状态]
        G2[标记AI摘要为无效]
        G3[更新区块链状态]
        G1 --> G2 --> G3
    end

    A3 --> B1
    B4 --> C1
    C2 --> D1
    B3 --> D1
    
    D4 -.-> E1
    C2 -.-> E2
    A3 -.-> E3
    
    A3 --> F2
    F1 --> F2
    C2 --> F3
    
    D4 -.-> G1

    subgraph 智能合约AITracerContract
        H1[存储记录]
        H2[检索记录]
        H3[验证所有权]
        H4[更新状态]
        H1 <--> H2
        H2 <--> H3
        H3 <--> H4
    end
    
    D2 --> H1
    E1 --> H2
    G2 --> H3 --> H4
