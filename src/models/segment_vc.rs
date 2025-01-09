use alloy_primitives::{B256, U256};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::error::Error as StdError;
use std::{fmt};
use sp1_zkvm::io::{self as spio};
use super::CircularHashStore;
use crate::BoxError;

// 常量定义
const SEGMENT_SIZE: usize = 16; // 每段16个元素
const CHUNK_SIZE: usize = 16; // 每chunk16个元素
const NODE_WIDTH: usize = 16; // 节点宽度
const TREE_DEPTH: usize = 10; // 树的深度
                              // 计算左叶子节点索引的常量函数
const fn calculate_left_leaf_index() -> usize {
    // 在16叉树中，计算最左边叶子节点的索引
    // 对于深度为d的16叉树，最左叶子节点的索引为 (16^d - 1) / 15
    // 其中 16^d = 16^10 = 1,152,921,504,606,846,976

    // 使用 u128 来处理大数计算
    const NUMERATOR: u128 = 1_152_921_504_606_846_975; // 16^10 - 1
    // const NUMERATOR: u128 = 1048575; // 16^10 - 1
    const DENOMINATOR: u128 = NODE_WIDTH as u128 - 1; // 16 - 1 = 15
    const RESULT: u128 = NUMERATOR / DENOMINATOR; // 76,861,433,640,456,465

    // 确保结果不超过 usize 的范围
    assert!(RESULT <= u128::MAX as u128, "LEFT_LEAF_INDEX too large");
    RESULT as usize
}

// 定义为常量
const LEFT_LEAF_INDEX: usize = calculate_left_leaf_index();
// 错误定义
#[derive(Debug, PartialEq)]
pub enum Error {
    KeyExists,
    KeyNotFound,
    IndexOutOfBounds,
    InvalidProof,
    HashStoreError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::KeyExists => write!(f, "Key already exists"),
            Error::KeyNotFound => write!(f, "Key not found"),
            Error::IndexOutOfBounds => write!(f, "Index out of bounds"),
            Error::InvalidProof => write!(f, "Invalid proof"),
            Error::HashStoreError(msg) => write!(f, "Hash store error: {}", msg),
        }
    }
}

impl StdError for Error {}
#[derive(Debug, Clone,Serialize,Deserialize)]
pub struct ValueProof {
    pub value: B256,      // 原始值
    pub chunk_hash: B256, // 对应的chunk hash
}

#[derive(Debug, Clone,Serialize,Deserialize)]
pub struct SegmentProof {
    pub chunk_index: usize,  // chunk在segment内的索引
    pub siblings: Vec<B256>, // 同segment内的其他chunk hashes
}

#[derive(Debug, Clone,Serialize,Deserialize)]
pub struct LevelProof {
    pub level: usize,        // 当前层级
    pub node_index: usize,   // 节点在当前层的索引
    pub siblings: Vec<B256>, // 同组内的其他节点hashes
}

#[derive(Debug, Clone,Serialize,Deserialize)]
pub struct MerkleProof {
    pub value_proof: ValueProof,       // 值到chunk hash的证明
    pub segment_proof: SegmentProof,   // chunk在segment内的证明
    pub level_proofs: Vec<LevelProof>, // 从Level 0到root的路径证明
    pub root_hash: B256,               // 最终的root hash
}
impl MerkleProof {
    pub fn read_from_stdin() -> Self {
        // 1. 读取 ValueProof
        let value_proof = ValueProof {
            value: spio::read(),
            chunk_hash: spio::read(),
        };

        // 2. 读取 SegmentProof
        let chunk_index = spio::read::<u32>() as usize;
        let siblings_len = spio::read::<u32>() as usize;
        let mut segment_siblings = Vec::with_capacity(siblings_len);
        for _ in 0..siblings_len {
            segment_siblings.push(spio::read::<B256>());
        }
        let segment_proof = SegmentProof {
            chunk_index,
            siblings: segment_siblings,
        };

        // 3. 读取 LevelProofs
        let level_proofs_len = spio::read::<u32>() as usize;
        let mut level_proofs = Vec::with_capacity(level_proofs_len);
        
        for _ in 0..level_proofs_len {
            let level = spio::read::<u32>() as usize;
            let node_index = spio::read::<u32>() as usize;
            let level_siblings_len = spio::read::<u32>() as usize;
            
            let mut level_siblings = Vec::with_capacity(level_siblings_len);
            for _ in 0..level_siblings_len {
                level_siblings.push(spio::read::<B256>());
            }

            level_proofs.push(LevelProof {
                level,
                node_index,
                siblings: level_siblings,
            });
        }

        // 4. 读取根哈希
        let root_hash = spio::read::<B256>();

        Self {
            value_proof,
            segment_proof,
            level_proofs,
            root_hash,
        }
    }
}




impl MerkleProof {
    pub fn verify(&self) -> Result<bool, BoxError> {
        print_proof(&self, "---------------------- in ---------------");
        println!("\n=== Starting Verification Process ===");

        // 1. 验证value到chunk hash
        let mut hasher = Keccak256::new();
        hasher.update(self.value_proof.value.as_slice());
        let calculated_chunk = B256::from_slice(&hasher.finalize());
        println!("Value -> Chunk Hash:");
        println!(
            "  Value:           {}",
            format_hash(&self.value_proof.value)
        );
        println!("  Calculated:      {}", format_hash(&calculated_chunk));
        println!(
            "  Expected Chunk:  {}",
            format_hash(&self.value_proof.chunk_hash)
        );

        if calculated_chunk != self.value_proof.chunk_hash {
            return Ok(false);
        }

        if self.segment_proof.siblings.len() == 0 {
            if (self.root_hash == calculated_chunk &&  calculated_chunk == self.value_proof.chunk_hash) {
                return Ok(true);
            }
        }

        // 2. 验证chunk hash到segment root

        let len = self.segment_proof.siblings.len() + 1;
        let mut all_chunks = vec![B256::default(); len];
        all_chunks[self.segment_proof.chunk_index] = self.value_proof.chunk_hash;

        // 填充其他chunk hashes
        let mut sibling_idx = 0;
        //填充左边
        for i in 0..len {
            if i != self.segment_proof.chunk_index {
                all_chunks[i] = self.segment_proof.siblings[sibling_idx];
                sibling_idx += 1;
            }
        }
        hasher = Keccak256::new();
        // 计算segment root
        println!("\n chunks: {}, index:{}, siblings:{:?}",len,self.segment_proof.chunk_index,self.segment_proof.siblings);
        for chunk in all_chunks {
             println!("[{}],",format_hash(&chunk));
            hasher.update(chunk.as_slice());
        }
        let mut current_hash = B256::from_slice(&hasher.finalize());
        println!("\nChunk Hash -> Segment Root:");
        println!("  Segment Root: {}", format_hash(&current_hash));

        // 3. 验证从Level 0到root的路径
        for proof in &self.level_proofs {
            println!("\nLevel {} (index {}):", proof.level, proof.node_index);
            hasher = Keccak256::new();
            let len = proof.siblings.len() + 1;
            // 构建当前层的所有节点
            let mut level_nodes = vec![B256::default(); len];
            level_nodes[proof.node_index] = current_hash;

            // 填充兄弟节点
            let mut sibling_idx = 0;
            for i in 0..len {
                if i != proof.node_index {
                    if sibling_idx < proof.siblings.len() {
                        level_nodes[i] = proof.siblings[sibling_idx];
                        sibling_idx += 1;
                    }
                }
            }

            // 计算父节点
            for (i, node) in level_nodes.iter().enumerate() {
                println!("  Node[{}]: {}", i, format_hash(node));
                hasher.update(node.as_slice());
            }

            current_hash = B256::from_slice(&hasher.finalize());
            println!("  Result: {}", format_hash(&current_hash));
        }

        println!("\nFinal Verification:");
        println!("Calculated Root: {}", format_hash(&current_hash));
        println!("Expected Root:   {}", format_hash(&self.root_hash));

        Ok(current_hash == self.root_hash)
    }
}
#[derive(Debug)]
pub enum BuilderMode {
    Building,
    Built,
}
#[derive(Debug, Clone)]
struct Segment {
    values: Vec<B256>,       // 值数组
    chunk_hashes: Vec<B256>, // chunk哈希数组
    root: B256,              // 段根
    size: usize,             // 当前使用数量
}
pub struct SegmentVC {
    segments: Vec<Segment>,                  // 所有段
    total_size: usize,                       // 总元素数量
    root_hash: B256,                         // 根哈希
    merkle_nodes: HashMap<usize, Vec<B256>>, // merkle树节点存储
    indices: HashMap<B256, usize>,           // 键到索引的映射
    root_history: CircularHashStore,         // 根哈希历史
    // 新增构建模式相关字段
    building_mode: BuilderMode,
}

impl SegmentVC {
    pub fn new(capacity: usize) -> Self {
        let mut segments = Vec::new();
        segments.push(Segment {
            values: Vec::new(),
            chunk_hashes: Vec::new(),
            root: B256::default(),
            size: 0,
        });

        Self {
            segments,
            total_size: 0,
            root_hash: B256::default(),
            merkle_nodes: HashMap::new(),
            indices: HashMap::new(),
            root_history: CircularHashStore::new(capacity),
            building_mode: BuilderMode::Built,
        }
    }
    // 获取根哈希
    pub fn get_root_hash(&self) -> B256 {
        self.root_hash
    }
// 新增：开始构建模式
pub fn start_building(&mut self) {
    self.building_mode = BuilderMode::Building;
}

// 新增：完成构建
pub fn finish_building(&mut self) -> Result<B256, BoxError> {
    // 只有在构建模式下才需要重新计算
    if matches!(self.building_mode, BuilderMode::Building) {
        // 重新计算所有segment的chunk hashes和roots
        for segment_index in 0..self.segments.len() {
            let segment = &self.segments[segment_index];
            let values = segment.values.clone();
            for (local_index, value) in values.iter().enumerate() {
                if *value != B256::default() {
                    self.update_segment(segment_index, local_index, *value)?;
                }
            }
        }

        // 更新整个Merkle树
        if self.segments.len() > 0 {
            self.update_merkle_tree(0)?;
        }

        self.building_mode = BuilderMode::Built;
    }

    Ok(self.root_hash)
}

    pub fn insert(&mut self, key: B256, value: B256) -> Result<B256, BoxError> {
        if self.indices.contains_key(&key) {
            return Err(Box::new(Error::KeyExists));
        }

        let (current_segment, local_index) = self.get_segment_and_index(self.total_size);

        // 确保有足够的段
        while self.segments.len() <= current_segment {
            self.segments.push(Segment {
                values: Vec::new(),
                chunk_hashes: Vec::new(),
                root: B256::default(),
                size: 0,
            });
        }

        self.total_size += 1;
        self.indices.insert(key, self.total_size);

        // // 更新段内容
        // {
        //     let segment = &mut self.segments[current_segment];
        //     segment.size += 1;
        //     self.update_segment(current_segment, local_index, value)?;
        // }

        // // 更新merkle树
        // self.update_merkle_tree(current_segment)
          // 更新段内容
          {
            let segment = &mut self.segments[current_segment];
            // segment.size += 1;
            
            // 确保values数组有足够空间
            while segment.values.len() <= local_index {
                segment.values.push(B256::default());
            }
            segment.values[local_index] = value;

            // 只在非构建模式下更新segment和merkle树
            if matches!(self.building_mode, BuilderMode::Built) {
                self.update_segment(current_segment, local_index, value)?;
                return self.update_merkle_tree(current_segment);
            }
        }
        Ok(self.root_hash)
    }
   // 新增：批量插入方法
   pub fn insert_batch(&mut self, entries: Vec<(B256, B256)>) -> Result<B256, BoxError> {
    self.start_building();
    
    for (key, value) in entries {
        self.insert(key, value)?;
    }

    self.finish_building()
}
    pub fn generate_proof(&self, key: B256) -> Result<MerkleProof, BoxError> {
        let index = self.indices.get(&key).ok_or(Error::KeyNotFound)?;
        let (segment_index, local_index) = self.get_segment_and_index(index - 1);

        // 1. 构建value proof
        let value = self.segments[segment_index].values[local_index];
        let chunk_hash = self.segments[segment_index].chunk_hashes[local_index];
        let value_proof = ValueProof { value, chunk_hash };

        // 2. 构建segment proof
        let segment = &self.segments[segment_index];
        let mut chunk_siblings = Vec::new();
        for i in 0..segment.chunk_hashes.len() {
            if i != local_index {
                chunk_siblings.push(segment.chunk_hashes[i]);
            }
        }
        let segment_proof = SegmentProof {
            chunk_index: local_index,
            siblings: chunk_siblings,
        };

        // 3. 构建level proofs
        let mut level_proofs = Vec::new();
        let mut current_index = segment_index;

        for level in 0..self.merkle_nodes.len() - 1 {
            let nodes = &self.merkle_nodes[&level];
            let group_start = (current_index / SEGMENT_SIZE) * SEGMENT_SIZE;
            let group_end = std::cmp::min(group_start + SEGMENT_SIZE, nodes.len());

            let mut siblings = Vec::new();
            for i in group_start..group_end {
                if i != current_index {
                    siblings.push(nodes[i]);
                }
            }

            level_proofs.push(LevelProof {
                level,
                node_index: current_index % SEGMENT_SIZE,
                siblings,
            });

            current_index /= SEGMENT_SIZE;
        }

        Ok(MerkleProof {
            value_proof,
            segment_proof,
            level_proofs,
            root_hash: self.root_hash,
        })
    }
    // ... 其他辅助方法保持不变
}
impl SegmentVC {
    fn update_segment(
        &mut self,
        segment_index: usize,
        local_index: usize,
        value: B256,
    ) -> Result<(), BoxError> {
        {
            let segment = &mut self.segments[segment_index];
            while segment.values.len() <= local_index {
                segment.values.push(B256::default());
            }
            segment.values[local_index] = value;
        }
        // 2. 计算chunk hash
        let segment = &mut self.segments[segment_index];
        segment.chunk_hashes.clear(); // 清除现有的chunk hashes

        // 只为实际存在的值计算chunk hash
        for i in 0..segment.values.len() {
            let value = segment.values[i];
            let mut hasher = Keccak256::new();
            hasher.update(value.as_slice());
            let chunk_hash = B256::from_slice(&hasher.finalize());
            segment.chunk_hashes.push(chunk_hash);
        }
        // 3. 计算chunk root
        let mut hasher = Keccak256::new();
        for hash in &segment.chunk_hashes {
            hasher.update(hash.as_slice());
        }
        segment.root = B256::from_slice(&hasher.finalize());

        Ok(())
    }

    // 更新Merkle树
    fn update_merkle_tree(&mut self, segment_index: usize) -> Result<B256, BoxError> {
        println!("\n=== Updating Merkle Tree ===");

        // 清除旧的merkle nodes数据
        // self.merkle_nodes.clear();

        // 1. 从segment roots开始，作为第0层
        let mut current_level_nodes = self
            .segments
            .iter()
            .map(|seg| seg.root)
            .collect::<Vec<B256>>();

        println!("\nLevel 0 (Segment Roots):");
        for (i, node) in current_level_nodes.iter().enumerate() {
            println!("Node[{}]: {}", i, format_hash(node));
        }
        // 存储第0层数据
        self.merkle_nodes.insert(0, current_level_nodes.clone());

        // 2. 逐层向上构建，每SEGMENT_SIZE个节点构建一个父节点
        let mut level = 0;
        while current_level_nodes.len() > 1 {
            level += 1;
            let mut next_level = Vec::new();

            // println!("\nProcessing Level {}:", level);

            // 每SEGMENT_SIZE个节点一组
            for (group_idx, chunk) in current_level_nodes.chunks(SEGMENT_SIZE).enumerate() {
                // println!("\nProcessing Group {}:", group_idx);

                let mut hasher = Keccak256::new();
                for (i, node) in chunk.iter().enumerate() {
                    // println!("  Node[{}]: {}", i, format_hash(node));
                    hasher.update(node.as_slice());
                }

                let parent = B256::from_slice(&hasher.finalize());
                // println!("  Group Hash: {}", format_hash(&parent));
                next_level.push(parent);
            }

            // 存储当前层的数据
            self.merkle_nodes.insert(level, next_level.clone());
            current_level_nodes = next_level;
        }

        // 3. 设置最终的root hash
        self.root_hash = current_level_nodes[0];
        println!("\nFinal root hash: {}", format_hash(&self.root_hash));

        self.root_history.add_hash(self.root_hash)?;
        Ok(self.root_hash)
    }

    // 辅助函数：检查节点是否有兄弟节点
    fn has_siblings(&self, node_index: usize) -> bool {
        let parent_index = self.get_parent_node_index(node_index);
        let left_child = parent_index * NODE_WIDTH + 1;

        for i in left_child..left_child + NODE_WIDTH {
            if i != node_index {
                if let Some(hash) = self.merkle_nodes.get(&i) {
                    if hash.len() > 0 {
                        return true;
                    }
                }
            }
        }
        false
    }

    // 获取父节点索引
    fn get_parent_node_index(&self, index: usize) -> usize {
        (index - 1) / NODE_WIDTH
    }

    // 获取叶子节点索引
    fn get_leaf_node_index(&self, segment_index: usize) -> usize {
        let leaf_index = LEFT_LEAF_INDEX + segment_index;
        self.get_parent_node_index(leaf_index)
    }

    // 获取segment和本地索引
    fn get_segment_and_index(&self, global_index: usize) -> (usize, usize) {
        let segment_index = global_index / SEGMENT_SIZE;
        let local_index = global_index % SEGMENT_SIZE;
        (segment_index, local_index)
    }

    // 验证特定值
    pub fn verify(&self, key: B256, value: B256, history_root: B256) -> Result<bool, BoxError> {
        let index = self.indices.get(&key).ok_or(Error::KeyNotFound)?;
        let (segment_index, local_index) = self.get_segment_and_index(index - 1);

        let segment = &self.segments[segment_index];
        if value != segment.values[local_index] {
            return Ok(false);
        }

        Ok(history_root == self.root_hash || self.root_history.check_hash(history_root, &[]))
    }

    // 获取值
    pub fn get_value(&self, key: B256) -> Result<B256, BoxError> {
        let index = self.indices.get(&key).ok_or(Error::KeyNotFound)?;
        let (segment_index, local_index) = self.get_segment_and_index(index - 1);
        Ok(self.segments[segment_index].values[local_index])
    }

    // 更新值
    pub fn update(&mut self, key: B256, value: B256) -> Result<B256, BoxError> {
        let index = self.indices.get(&key).ok_or(Error::KeyNotFound)?;
        let (segment_index, local_index) = self.get_segment_and_index(index - 1);

        self.update_segment(segment_index, local_index, value)?;
        self.update_merkle_tree(segment_index)
    }
}
fn format_hash(hash: &B256) -> String {
    let bytes = hash.as_slice();
    format!(
        "{:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[28], bytes[29], bytes[30], bytes[31]
    )
}

pub fn print_proof(proof: &MerkleProof, title: &str) {
    println!("\n=== {} ===", title);

    // 打印Value Proof
    println!("Value Proof:");
    println!(
        "  Original Value: {}",
        format_hash(&proof.value_proof.value)
    );
    println!(
        "  Chunk Hash:     {}",
        format_hash(&proof.value_proof.chunk_hash)
    );

    // 打印Segment Proof
    println!("\nSegment Proof:");
    println!("  Chunk Index: {}", proof.segment_proof.chunk_index);
    println!("  Siblings:");
    for (i, sibling) in proof.segment_proof.siblings.iter().enumerate() {
        println!("    {}: {}", i, format_hash(sibling));
    }

    // 打印Level Proofs
    println!("\nLevel Proofs:");
    for level_proof in proof.level_proofs.iter() {
        println!("\nLevel {}:", level_proof.level);
        println!("  Node Index: {}", level_proof.node_index);
        println!("  Siblings:");
        for (i, sibling) in level_proof.siblings.iter().enumerate() {
            println!("    {}: {}", i, format_hash(sibling));
        }
    }

    println!("\nRoot Hash: {}", format_hash(&proof.root_hash));
}
impl SegmentVC {
    pub fn print_tree_structure(&self) {
        println!("\n=== Vector Commitment Tree Structure ===\n");

        // 找出最大层级
        let max_level = self.merkle_nodes.keys().max().unwrap_or(&0);

        // 从上到下打印每一层
        // 最顶层（root）
        println!("Root Hash: {}", format_hash(&self.root_hash));

        // 打印merkle_nodes中的每一层
        for level in (0..=*max_level).rev() {
            if let Some(nodes) = self.merkle_nodes.get(&level) {
                println!("\nLevel {}:", level);
                for (i, node) in nodes.iter().enumerate() {
                    println!("├── Node[{}]: {}", i, format_hash(node));
                }
            }
        }

        // 打印Segment Roots
        println!("\nSegment Roots:");
        for (i, segment) in self.segments.iter().enumerate() {
            println!("├── Segment[{}]: {}", i, format_hash(&segment.root));
        }

        // 打印Chunk Hashes
        println!("\nChunk Hashes:");
        for (seg_idx, segment) in self.segments.iter().enumerate() {
            println!("Segment {}:", seg_idx);
            for (i, chunk_hash) in segment.chunk_hashes.iter().enumerate() {
                println!("├── Chunk[{}]: {}", i, format_hash(chunk_hash));
            }
        }

        // 打印Original Values
        println!("\nOriginal Values:");
        for (seg_idx, segment) in self.segments.iter().enumerate() {
            println!("Segment {}:", seg_idx);
            for (i, value) in segment.values.iter().enumerate() {
                println!("├── Value[{}]: {}", i, format_hash(value));
            }
        }

        println!("\nTotal size: {}", self.total_size);

        // 打印一些统计信息
        println!("\nTree Statistics:");
        println!("Total Levels: {}", max_level + 1);
        println!("Total Segments: {}", self.segments.len());
        println!("Nodes per Level:");
        for level in 0..=*max_level {
            if let Some(nodes) = self.merkle_nodes.get(&level) {
                println!("  Level {}: {} nodes", level, nodes.len());
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_node_proof() -> Result<(), BoxError> {
        let mut vc = SegmentVC::new(16);

        let key = B256::from([1u8;32]);
        let value = B256::from([100u8;32]);
        vc.insert(key, value)?;

        let proof = vc.generate_proof(key)?;
        print_proof(&proof, "Single Node Proof");
        assert!(proof.verify()?);

        Ok(())
    }

    #[test]
    fn test_multiple_nodes_proof() -> Result<(), BoxError> {
        let mut vc = SegmentVC::new(16);

        // 插入多个节点
        for i in 1..4 {
            let key = B256::repeat_byte(i as u8);
            let value = B256::repeat_byte((i * 100) as u8);
            vc.insert(key, value)?;
        }
        // 打印整个树的结构
        vc.print_tree_structure();
        // 验证不同位置的节点
        let test_indices = vec![1, 3];
        for &i in &test_indices {
            let key = B256::repeat_byte(i as u8);
            let proof = vc.generate_proof(key)?;
            print_proof(&proof, &format!("Node {} Proof", i));
            assert!(proof.verify()?);
        }

        Ok(())
    }
    #[test]
    fn test_three_nodes_tree() -> Result<(), BoxError> {
        let mut vc = SegmentVC::new(128);

        // 创建三个不同的值和key
        let key1 = B256::repeat_byte(1 as u8);
        let key2 = B256::repeat_byte(2 as u8);
        let key3 = B256::repeat_byte(3 as u8);

        let value1 = B256::repeat_byte(100 as u8);
        let value2 = B256::repeat_byte(200 as u8);
        let value3 = B256::repeat_byte((300&0xff) as u8);

        println!("\n=== Inserting First Node ===");
        vc.insert(key1, value1)?;

        println!("\n=== Inserting Second Node ===");
        vc.insert(key2, value2)?;

        println!("\n=== Inserting Third Node ===");
        vc.insert(key3, value3)?;

        vc.print_tree_structure();

        // 生成并验证每个节点的证明
        for (key, value) in [(key1, value1), (key2, value2), (key3, value3)] {
            println!(
                "\n=== Generating and Verifying Proof for key {} ===",
                format_hash(&key)
            );
            let proof = vc.generate_proof(key)?;
            print_proof(&proof, &format!("Node {} Proof", key));
            assert!(proof.verify()?);
        }

        Ok(())
    }

    #[test]
    fn test_building_mode() -> Result<(), BoxError> {
        let mut vc = SegmentVC::new(16);
        
        // 开始构建模式
        vc.start_building();

        // 插入多个值
        for i in 1..=5 {
            let key = B256::repeat_byte(i as u8);
            let value = B256::repeat_byte(((100* i)&0xff) as u8);
            vc.insert(key, value)?;
        }

        // 完成构建
        let root = vc.finish_building()?;

        // 验证所有值
        for i in 1..=5 {
            let key = B256::repeat_byte(i as u8);
            let value = vc.get_value(key)?;
            assert_eq!(value, B256::repeat_byte(((i*100)&0xff) as u8));
        }

        Ok(())
    }

    #[test]
    fn test_batch_insert() -> Result<(), BoxError> {
        let mut vc = SegmentVC::new(16);

        // 准备批量数据
        let entries: Vec<(B256, B256)> = (1..=5)
            .map(|i| (
                B256::repeat_byte(i as u8),
                B256::repeat_byte(((i*100 as u32)&0xff) as u8)
            ))
            .collect();

        // 批量插入
        let root = vc.insert_batch(entries.clone())?;

        // 验证所有值
        for (key, expected_value) in entries {
            let value = vc.get_value(key)?;
            assert_eq!(value, expected_value);
        }

        Ok(())
    }

    #[test]
    fn test_mixed_mode() -> Result<(), BoxError> {
        let mut vc = SegmentVC::new(16);

        // 正常模式插入
        let key1 = B256::repeat_byte(1 as u8);
        let value1 = B256::repeat_byte(100 as u8);
        vc.insert(key1, value1)?;

        // 构建模式批量插入
        let entries: Vec<(B256, B256)> = (2..=4)
            .map(|i| (
                B256::repeat_byte(i as u8),
                B256::repeat_byte(((i*100)&0xff) as u8)
            ))
            .collect();
        vc.insert_batch(entries)?;

        // 再次正常模式插入
        let key5 = B256::repeat_byte(5 as u8);
        let value5 = B256::repeat_byte((500&0xff) as u8);
        vc.insert(key5, value5)?;

        // 验证所有值
        for i in 1..=5 {
            let key = B256::repeat_byte(i as u8);
            let value = vc.get_value(key)?;
            assert_eq!(value, B256::repeat_byte(((i*100)&0xFF) as u8));
        }

        Ok(())
    }
}
