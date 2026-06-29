# SecureCore — 绝对盲密码内核

**后量子、零服务器、点对点加密消息后端。**

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[English](README.md) | **中文**

SecureCore 是 **LinkChat** 的本地密码学内核 —— 面向敌手同时控制网络、服务器且最终拥有量子计算机的威胁模型。它通过 22 个 `extern "C"` 函数暴露扁平 C ABI，经由薄 FFI 桥接层从 Swift (iOS) 或 Kotlin (Android) 调用。

---

## 设计哲学

### 1. 仅三个全局量

会话的整个持久化密码学状态仅由三个值组成：

```
ROOT_STATE_CURR  : [u8; 32]   — 当前 256 位根密钥
ROOT_STATE_PEND  : Option<[u8; 32]> — 待处理的后量子替代密钥
EPOCH_ID         : u32        — 会话 epoch 计数器
```

无逐消息棘轮链、无预读密钥队列、无磁盘计数器链。每条消息密钥通过 HKDF-SHA256 从 `RootState_curr` 结合 epoch 内原子递增的消息序号实时派生。

### 2. 物理信任根

初始密钥材料通过 USB-C + BLE 带外交换。Alice 和 Bob 各自贡献熵字节，奇偶交错哈希经 SHA-256 生成初始 `RootState`。不存在可供未来量子计算机追溯解密的非对称密钥交换流量。

### 3. 后量子前向安全

密钥轮换使用 **ML-KEM-1024**（NIST FIPS 203，Category 5 安全等级）。三步协议——待处理（封装）、交换（盲中继）、提交（原子提升）——将 `RootState_curr` 替换为新鲜 PQ 派生材料。解密路径上的自动提交检测确保双方无需额外往返即可收敛。

### 4. 恒定流封面流量

后台定时器每 5 秒触发。如有真实消息排队则发送；否则发送 4096 字节的 OsRng 白噪声数据包。所有数据包严格 4096 字节。对任何网络观察者而言，每个节点每时每刻都在发送同等大小的不可区分数据包——社交图谱被密码学隐藏。

### 5. 零服务器架构

无密钥目录。无预密钥服务器。无消息队列。无身份服务器。唯一网络依赖 TDLib 作为盲中继——它可见密文但无法解密、认证或关联会话。

---

## 理论基础

SecureCore 的密钥演化和自愈机制有配套研究论文提供形式化安全分析：

**[Post-Compromise Security Without External Entropy](docs/paper.pdf)** — *eprint.iacr.org, 2026*

论文证明了基于 PRP 的状态演化在**零外部熵**条件下实现紧致后妥协安全。LinkChat 通过 `commit_evolution` / `decrypt_with_auto_commit` 实现的单向自愈被证明是理论上最优的：敌手优势被界定在 τ/2^{λ+1} 与 τ/2^{λ} 之间，其中 τ 为愈合步数、λ 为安全参数。除初始根密钥外无需任何外部熵源。

*匿名。优先权通过 IACR eprint 时间戳确立。*

---

## 模块概览

| 模块 | 文件 | 功能 |
|:---|:---|:---|
| **FFI 桥接** | `lib.rs` | 全部 22 个 `extern "C"` 入口点 |
| **根状态** | `root_state.rs` | OnceLock<Mutex<>> 保护的三全局变量 |
| **初始化** | `init_module.rs` | USB-C 离线熵交错、ID_Stamp 派生 |
| **消息加密** | `message_cipher.rs` | AES-256-GCM 加解密 + HKDF 密钥派生 + 自动提交 PCS |
| **密钥演化** | `evolution.rs` | ML-KEM-1024 三相后量子密钥轮换 + MITM 检测 |
| **抗 DoS** | `anti_dos.rs` | 丢包后 epoch 前滚恢复 |
| **恒定流** | `constant_flow.rs` | 5s 定时器 + 4KB 固定包 + 白噪声填充 |
| **尾填充** | `tail_padding.rs` | 追加 [16,512] 字节 OsRng 噪声 |
| **虚拟卷** | `virtual_volume.rs` | 单文件 AES 加密保险库（`vault.sec`），每块 ChaCha20Poly1305 |
| **内存保护** | `memory_protection.rs` | SecureBuffer（释放即清零）+ 紧急退出 |
| **磁盘擦除** | `disk_wipe.rs` | 多次安全擦除：OsRng → 零 → 截断 → fsync |
| **时钟对齐** | `clock_align.rs` | 16 槽环形缓冲区自适应时钟偏差估计 |

---

## 密码学原语

| 算法 | 用途 |
|:---|:---|
| **AES-256-GCM** | 消息加密 |
| **ChaCha20Poly1305** | 保险库块存储 |
| **ML-KEM-1024** | 后量子密钥演化 |
| **HKDF-SHA256** | 消息密钥派生、演化、前滚 |
| **HMAC-SHA256** | 保险库逐块密钥派生 |
| **SHA-256** | ID_Stamp、RootState 初始化、公钥绑定 |
| **OsRng** | 所有 nonce、填充、噪声、擦除轮次 |

---

## 密钥生命周期

### 诞生——离线初始化
```
1. Bob 生成 ML-KEM-1024 密钥对
2. Alice + Bob 物理连接（USB-C + BLE）
3. Bob 发送：entropy_bytes + public_key
4. 奇偶交错 → SHA-256 → ROOT_STATE_CURR[32], EPOCH_ID = 0
5. 生成 id_stamp → 写入保险库 → 所有后续消息通过 AAD 绑定
```

### 使用——逐消息加密
```
msg_seq = 原子递增计数器
Message_Key = HKDF-Expand(ROOT_STATE_CURR, epoch || msg_seq) → 32 字节
AAD = [id_stamp || 方向 || epoch || msg_seq || 时间戳 || 协议版本]
密文格式: [12B nonce || AES-256-GCM 密文 || 16B GCM 标签]
→ 尾填充 → 恒定流填充至 4096 字节
```

### 轮换——后量子演化 (PCS)
```
阶段 1 (Alice): 封装 → 共享秘密 → RootState_pend，发送 KEM 密文
阶段 2 (Bob):   解封 → 相同秘密 → 相同 RootState_pend，提交并回复
阶段 3 (Alice): 解密失败 → 尝试 RootState_pend → 自动提交
```

### 恢复——抗 DoS Epoch 前滚
```
recover_after_loss(target_epoch): 逐 epoch HKDF 前滚，最大 100,000 epoch
```

---

## 安全属性

| 属性 | 状态 | 机制 |
|:---|:---|:---|
| 消息机密性 | ✅ | AES-256-GCM 逐消息 AEAD |
| 逐消息密钥独立 | ✅ | HKDF-Expand (epoch, msg_seq) |
| 跨 epoch 前向安全 | ✅ | ML-KEM-1024 三相密钥演化 |
| 后妥协安全 (PCS) | ✅ | 解密时自动提交 |
| 密文认证 | ✅ | GCM 16B 标签 + AAD 绑定 |
| 抗重放 | ⚠️ | 调用方需跟踪 max_seq_seen |
| 后量子安全 | ✅ | ML-KEM-1024 (Category 5) |
| 流量分析抵抗 | ✅ | 5s 恒定流 + 4KB 固定包 |
| 本地存储加密 | ✅ | ChaCha20Poly1305 逐块 AEAD |
| 可否认性 | ✅ | 纯对称密钥 + 一键销毁 |
| 防篡改 | ✅ | 蜜罐金丝雀块 + AEAD |
| 内存安全 | ✅ | SecureBuffer 释放即清零 |
| 零服务器信任 | ✅ | TDLib 仅盲中继 |

**不保护：** 已攻破设备（越狱/root）、Telegram 元数据、截屏/手动转发、社工攻击、未加密备份、物理胁迫。

---

## 已知局限

1. **无逐消息 DH 棘轮。** Epoch 级 PCS 需显式 ML-KEM 演化触发愈合。
2. **无异步消息。** 初始化和演化提交需双方同时在线。
3. **无多设备支持。** ID_Stamp 绑定单一配对会话。
4. **无 PBKDF2/Argon2。** 保险库主密钥直接使用 32 字节。
5. **消息序号计数器仅存内存。** 进程重启后重置为 1。
6. **单一保险库单例。** 每次仅可打开一个 `vault.sec`。
7. **Rust 层无网络 I/O。** 所有传输通过回调委托给 Swift/Kotlin。
8. **磁盘擦除为密码学级别。** APFS/SSD 磨损均衡阻止物理覆写保证。
9. **`register_touch` 为存根。** GUI 触摸跟踪未实现。
10. **时钟对齐前向查找已记录但未实现。**

---

## 对比 Signal 协议

| 属性 | Signal 协议 | SecureCore |
|:---|:---|:---|
| 初始密钥交换 | X3DH 网络协议 | USB-C + BLE 物理交错 |
| 逐消息 PCS | DH 棘轮（自动） | Epoch 级（显式触发） |
| PCS 愈合时间 | 1–2 往返 | 1 次 KEM 往返 |
| 后量子 | PQXDH（仅初始交换） | 全 ML-KEM-1024（所有轮换） |
| 元数据保护 | 无 | 恒定流封面流量 |
| 服务器依赖 | 强制（预密钥服务器） | 无（TDLib 盲中继） |
| 身份 | 非对称 Curve25519 | 对称 ID_Stamp (SHA-256) |
| 异步消息 | ✅ | ❌（仅同步） |

---

## 许可

MIT
