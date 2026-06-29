# SecureCore — Absolute Blind Cryptographic Kernel / 绝对盲密码内核

**Post-quantum, zero-server, peer-to-peer encrypted messaging backend.**
**后量子、零服务器、点对点加密消息后端。**

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[English](#english) | [中文](#中文)

---

<a name="english"></a>
## English

SecureCore is the native cryptographic kernel of **LinkChat** — a messaging system designed for threat models where the adversary controls the network, the server, and eventually has access to a cryptographically-relevant quantum computer. It exposes a flat C ABI via 22 `extern "C"` functions designed to be called from Swift (iOS) or Kotlin (Android) via a thin FFI bridge.

### Design Philosophy

**1. Three Globals Only.** The entire persistent cryptographic state of a session is exactly three values: `ROOT_STATE_CURR : [u8; 32]`, `ROOT_STATE_PEND : Option<[u8; 32]>`, `EPOCH_ID : u32`. No per-message ratchet chain, no look-ahead key queue, no counter chain stored on disk. Every message key is derived on-the-fly via HKDF-SHA256.

**2. Physical Trust Root.** Initial key material is exchanged out-of-band via USB-C + BLE. Alice and Bob each contribute entropy bytes, which are odd/even-interleaved and hashed via SHA-256 to produce the initial `RootState`. No asymmetric key exchange traffic exists for a future quantum computer to retroactively decrypt.

**3. Post-Quantum Forward Secrecy.** Key rotation uses **ML-KEM-1024** (NIST FIPS 203, Category 5). A three-phase protocol — Pending (encapsulation), Exchange (via blind relay), Commit (atomic promotion) — replaces `RootState_curr` with fresh PQ-derived material. Auto-commit detection on the decrypt path ensures both peers converge without an extra round-trip.

**4. Constant-Flow Cover Traffic.** A background timer fires every 5 seconds. Real messages are sent if queued; otherwise 4096-byte packets of OsRng white noise fill the channel. All packets are exactly 4096 bytes—the social graph is cryptographically hidden.

**5. Zero Server Architecture.** No key directory, pre-key server, message queue, or identity server. The only network dependency is TDLib as a blind relay—it sees ciphertext but cannot decrypt, authenticate, or correlate sessions.

### Theoretical Foundation

SecureCore's key evolution and self-healing mechanism is formally analyzed in the accompanying research paper:

**[Post-Compromise Security Without External Entropy](docs/paper.pdf)** — *eprint.iacr.org, 2026*

The paper proves that a PRP-based state evolution achieves **tight post-compromise security with zero external entropy**. The adversary's advantage is bounded between τ/2^{λ+1} and τ/2^{λ}. No external entropy source is required beyond the initial root key.

### Module Overview

| Module | File | Purpose |
|--------|------|---------|
| **FFI Bridge** | `lib.rs` | All 22 `extern "C"` entry points |
| **Root State** | `root_state.rs` | 3 globals protected by `OnceLock<Mutex<>>` |
| **Init** | `init_module.rs` | USB-C offline entropy interleave |
| **Message Cipher** | `message_cipher.rs` | AES-256-GCM + HKDF + auto-commit PCS |
| **Evolution** | `evolution.rs` | ML-KEM-1024 three-phase PQ key rotation |
| **Anti-DoS** | `anti_dos.rs` | Epoch roll-forward after packet loss |
| **Constant Flow** | `constant_flow.rs` | 5s timer + 4KB fixed-size packets |
| **Tail Padding** | `tail_padding.rs` | [16,512]B OsRng noise append |
| **Virtual Volume** | `virtual_volume.rs` | ChaCha20Poly1305 per-block AEAD vault |
| **Memory Protection** | `memory_protection.rs` | SecureBuffer zeroize-on-drop |
| **Disk Wipe** | `disk_wipe.rs` | Multi-pass secure vault destruction |
| **Clock Align** | `clock_align.rs` | 16-slot adaptive clock-skew estimator |

### Cryptographic Primitives

| Algorithm | Usage |
|-----------|-------|
| **AES-256-GCM** | Message encryption |
| **ChaCha20Poly1305** | Vault block storage |
| **ML-KEM-1024** | Post-quantum key evolution |
| **HKDF-SHA256** | Key derivation, evolution, roll |
| **HMAC-SHA256** | Per-block vault key derivation |
| **SHA-256** | ID_Stamp, RootState init, PK binding |
| **OsRng** | All nonces, padding, noise, wipe passes |

### Key Lifecycle

**Birth — Offline Init:** Bob generates ML-KEM-1024 keypair → physical USB-C + BLE exchange → entropy interleave → SHA-256 → `ROOT_STATE_CURR`, `EPOCH_ID=0`.

**Use — Per-Message:** `msg_seq` atomically increments → `Message_Key = HKDF-Expand(ROOT_STATE_CURR, epoch || msg_seq)` → AES-256-GCM encrypt with AAD binding → tail padding → constant-flow to 4096B.

**Rotate — PCS:** Alice encapsulates → `RootState_pend` via HKDF-Extract → sends KEM ct → Bob decapsulates, derives same pend, commits → Alice's decrypt fails, tries pend, auto-commits.

**Recover — Anti-DoS:** `recover_after_loss(target_epoch)` rolls forward epoch-by-epoch via HKDF (max 100,000 gap).

### Security Properties

| Property | Status | Mechanism |
|----------|--------|-----------|
| Message confidentiality | ✅ | AES-256-GCM per-message AEAD |
| Per-message key independence | ✅ | HKDF-Expand (epoch, msg_seq) |
| Cross-epoch forward secrecy | ✅ | ML-KEM-1024 three-phase evolution |
| Post-compromise security | ✅ | Auto-commit on decrypt |
| Ciphertext authentication | ✅ | GCM 16B tag + AAD binding |
| Anti-replay | ⚠️ | Caller tracks max_seq_seen |
| Post-quantum | ✅ | ML-KEM-1024 (Category 5) |
| Traffic analysis resistance | ✅ | 5s constant-flow + 4KB packets |
| Local storage encryption | ✅ | ChaCha20Poly1305 per-block AEAD |
| Deniability | ✅ | Symmetric keys only + one-click purge |
| Tamper detection | ✅ | Canary honeytraps + AEAD |
| Memory safety | ✅ | SecureBuffer zeroize-on-drop |
| Zero server trust | ✅ | TDLib blind relay only |

**Not protected:** compromised device, Telegram metadata, screenshots, social engineering, unencrypted backups, physical coercion.

### Comparison to Signal

| Property | Signal | SecureCore |
|----------|--------|------------|
| Initial key exchange | X3DH over network | USB-C + BLE physical |
| Per-message PCS | DH Ratchet (auto) | Epoch-level (explicit) |
| PCS healing time | 1–2 round-trips | 1 KEM round-trip |
| Post-quantum | PQXDH (initial only) | Full ML-KEM-1024 |
| Metadata protection | None | Constant-flow cover traffic |
| Server dependency | Mandatory | None (blind relay) |
| Async messaging | ✅ | ❌ |

### Known Limitations

1. No per-message DH ratchet — epoch-level PCS only.
2. No async messaging — both peers online for init/evolution.
3. No multi-device support.
4. No PBKDF2/Argon2 for vault key.
5. Message counter in-memory only.
6. Single vault singleton.
7. No network I/O in Rust.
8. Disk wipe is cryptographic, not physical.
9. `register_touch` is a stub.
10. Clock align forward-seek not implemented.

### License

MIT

---

<a name="中文"></a>
## 中文

SecureCore 是 **LinkChat** 的本地密码学内核 —— 面向敌手同时控制网络、服务器且最终拥有量子计算机的威胁模型。通过 22 个 `extern "C"` 函数暴露扁平 C ABI，经由薄 FFI 桥接层从 Swift (iOS) 或 Kotlin (Android) 调用。

### 设计哲学

**1. 仅三个全局量。** 会话的整个持久化密码学状态仅由三个值组成：`ROOT_STATE_CURR : [u8; 32]`、`ROOT_STATE_PEND : Option<[u8; 32]>`、`EPOCH_ID : u32`。无逐消息棘轮链、无预读密钥队列、无磁盘计数器链。每条消息密钥通过 HKDF-SHA256 实时派生。

**2. 物理信任根。** 初始密钥材料通过 USB-C + BLE 带外交换。Alice 和 Bob 各自贡献熵字节，奇偶交错哈希经 SHA-256 生成初始 `RootState`。不存在可供未来量子计算机追溯解密的非对称密钥交换流量。

**3. 后量子前向安全。** 密钥轮换使用 **ML-KEM-1024**（NIST FIPS 203，Category 5）。三步协议——待处理（封装）、交换（盲中继）、提交（原子提升）——将 `RootState_curr` 替换为新鲜 PQ 派生材料。解密路径上的自动提交检测确保双方无需额外往返即可收敛。

**4. 恒定流封面流量。** 后台定时器每 5 秒触发。有真实消息则发送；否则发送 4096 字节 OsRng 白噪声。所有数据包严格 4096 字节——社交图谱被密码学隐藏。

**5. 零服务器架构。** 无密钥目录、无预密钥服务器、无消息队列、无身份服务器。唯一网络依赖 TDLib 作为盲中继——可见密文但无法解密、认证或关联会话。

### 理论基础

SecureCore 的密钥演化和自愈机制有配套研究论文提供形式化安全分析：

**[Post-Compromise Security Without External Entropy](docs/paper.pdf)** — *eprint.iacr.org, 2026*

论文证明了基于 PRP 的状态演化在**零外部熵**条件下实现紧致后妥协安全。敌手优势被界定在 τ/2^{λ+1} 与 τ/2^{λ} 之间。除初始根密钥外无需任何外部熵源。

### 模块概览

| 模块 | 功能 |
|:---|:---|
| **FFI 桥接** | 全部 22 个 `extern "C"` 入口点 |
| **根状态** | `OnceLock<Mutex<>>` 保护的三全局变量 |
| **初始化** | USB-C 离线熵交错、ID_Stamp 派生 |
| **消息加密** | AES-256-GCM + HKDF 密钥派生 + 自动提交 PCS |
| **密钥演化** | ML-KEM-1024 三相后量子密钥轮换 |
| **抗 DoS** | 丢包后 epoch 前滚恢复 |
| **恒定流** | 5s 定时器 + 4KB 固定包 + 白噪声 |
| **尾填充** | [16,512]B OsRng 噪声追加 |
| **虚拟卷** | ChaCha20Poly1305 逐块 AEAD 保险库 |
| **内存保护** | `SecureBuffer` 释放即清零 |
| **磁盘擦除** | 多次安全擦除：随机 → 零 → 截断 → fsync |
| **时钟对齐** | 16 槽自适应时钟偏差估计 |

### 密码学原语

| 算法 | 用途 |
|:---|:---|
| **AES-256-GCM** | 消息加密 |
| **ChaCha20Poly1305** | 保险库块存储 |
| **ML-KEM-1024** | 后量子密钥演化 |
| **HKDF-SHA256** | 密钥派生、演化、前滚 |
| **HMAC-SHA256** | 保险库逐块密钥派生 |
| **SHA-256** | ID_Stamp、RootState 初始化 |
| **OsRng** | nonce、填充、噪声、擦除 |

### 密钥生命周期

**诞生：** Bob 生成 ML-KEM-1024 密钥对 → USB-C + BLE 物理交换 → 熵交错 → SHA-256 → `ROOT_STATE_CURR`、`EPOCH_ID=0`。

**使用：** `msg_seq` 原子递增 → `Message_Key = HKDF-Expand(ROOT_STATE_CURR, epoch || msg_seq)` → AES-256-GCM 加密（AAD 绑定）→ 尾填充 → 恒定流至 4096B。

**轮换 (PCS)：** Alice 封装 → `RootState_pend` → 发送 KEM 密文 → Bob 解封、派生相同 pend、提交 → Alice 解密失败、尝试 pend、自动提交。

**恢复：** `recover_after_loss(target_epoch)` 逐 epoch HKDF 前滚（最大 100,000）。

### 安全属性

| 属性 | 状态 | 机制 |
|:---|:---|:---|
| 消息机密性 | ✅ | AES-256-GCM 逐消息 AEAD |
| 逐消息密钥独立 | ✅ | HKDF-Expand (epoch, msg_seq) |
| 跨 epoch 前向安全 | ✅ | ML-KEM-1024 三相密钥演化 |
| 后妥协安全 (PCS) | ✅ | 解密时自动提交 |
| 密文认证 | ✅ | GCM 16B 标签 + AAD 绑定 |
| 抗重放 | ⚠️ | 调用方跟踪 max_seq_seen |
| 后量子 | ✅ | ML-KEM-1024 (Category 5) |
| 流量分析抵抗 | ✅ | 5s 恒定流 + 4KB 固定包 |
| 本地存储加密 | ✅ | ChaCha20Poly1305 逐块 AEAD |
| 可否认性 | ✅ | 纯对称密钥 + 一键销毁 |
| 防篡改 | ✅ | 蜜罐金丝雀块 + AEAD |
| 内存安全 | ✅ | SecureBuffer 释放即清零 |
| 零服务器信任 | ✅ | TDLib 仅盲中继 |

**不保护：** 已攻破设备、Telegram 元数据、截屏/转发、社工、未加密备份、物理胁迫。

### 对比 Signal

| 属性 | Signal | SecureCore |
|:---|:---|:---|
| 初始密钥交换 | X3DH 网络协议 | USB-C + BLE 物理 |
| 逐消息 PCS | DH 棘轮（自动） | Epoch 级（显式触发） |
| PCS 愈合时间 | 1–2 往返 | 1 次 KEM 往返 |
| 后量子 | PQXDH（仅初始） | 全 ML-KEM-1024 |
| 元数据保护 | 无 | 恒定流封面流量 |
| 服务器依赖 | 强制 | 无（盲中继） |
| 异步消息 | ✅ | ❌ |

### 已知局限

1. 无逐消息 DH 棘轮。
2. 无异步消息。
3. 无多设备支持。
4. 无 PBKDF2/Argon2。
5. 消息计数器仅存内存。
6. 单一保险库单例。
7. Rust 层无网络 I/O。
8. 磁盘擦除为密码学级别。
9. `register_touch` 为存根。
10. 时钟对齐前向查找未实现。

### 许可

MIT
