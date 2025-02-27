// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AITracerContract {
    // 存储AI摘要记录的结构
    struct AIDigestRecord {
        string ipfsHash;      // IPFS哈希指针
        uint256 signatureE;   // 签名参数e
        uint256 signatureS;   // 签名参数s
        address owner;        // 记录所有者
        uint256 timestamp;    // 时间戳
        bool isValid;         // 有效性标志
    }
    
    // AI摘要记录映射表
    mapping(string => AIDigestRecord) public aiDigestRecords;
    
    // 记录所有IPFS哈希的数组
    string[] public allIpfsHashes;
    
    // 记录AI摘要的事件
    event AIDigestRecorded(string ipfsHash, address owner, uint256 timestamp);
    
    // 记录AI摘要
    function recordAIDigest(
        string memory ipfsHash,
        uint256 signatureE,
        uint256 signatureS
    ) public {
        // 确保哈希不为空
        require(bytes(ipfsHash).length > 0, "IPFS hash cannot be empty");
        
        // 确保记录不存在
        require(aiDigestRecords[ipfsHash].timestamp == 0, "AI digest already exists");
        
        // 创建新记录
        AIDigestRecord memory newRecord = AIDigestRecord({
            ipfsHash: ipfsHash,
            signatureE: signatureE,
            signatureS: signatureS,
            owner: msg.sender,
            timestamp: block.timestamp,
            isValid: true
        });
        
        // 存储记录
        aiDigestRecords[ipfsHash] = newRecord;
        allIpfsHashes.push(ipfsHash);
        
        // 触发事件
        emit AIDigestRecorded(ipfsHash, msg.sender, block.timestamp);
    }
    
    // 获取AI摘要记录
    function getAIDigestRecord(string memory ipfsHash) public view returns (
        string memory,
        uint256,
        uint256,
        address,
        uint256,
        bool
    ) {
        AIDigestRecord memory record = aiDigestRecords[ipfsHash];
        require(record.timestamp > 0, "AI digest not found");
        
        return (
            record.ipfsHash,
            record.signatureE,
            record.signatureS,
            record.owner,
            record.timestamp,
            record.isValid
        );
    }
    
    // 获取所有IPFS哈希的数量
    function getAIDigestCount() public view returns (uint256) {
        return allIpfsHashes.length;
    }
    
    // 标记AI摘要为无效（仅所有者可操作）
    function invalidateAIDigest(string memory ipfsHash) public {
        require(aiDigestRecords[ipfsHash].timestamp > 0, "AI digest not found");
        require(aiDigestRecords[ipfsHash].owner == msg.sender, "Only owner can invalidate");
        
        aiDigestRecords[ipfsHash].isValid = false;
    }
}