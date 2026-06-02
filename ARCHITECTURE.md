# 架构设计文档

> 项目：acme-client — 基于 ACME V2 协议 (RFC 8555) 的 Let's Encrypt 客户端  
> 命名空间：`Jason\Acme\`  
> 语言：PHP 8.3+

---

## 目录

- [1. 总体架构概览](#1-总体架构概览)
- [2. 设计模式分析](#2-设计模式分析)
  - [2.1 Facade（外观模式）— 主导模式](#21-facade外观模式--主导模式)
  - [2.2 DTO（数据传输对象）](#22-dto数据传输对象)
  - [2.3 依赖注入（DI）](#23-依赖注入di)
  - [2.4 策略模式（轻量实现）](#24-策略模式轻量实现)
- [3. 类职责矩阵](#3-类职责矩阵)
- [4. 数据流：证书签发生命周期](#4-数据流证书签发生命周期)
- [5. 安全设计要点](#5-安全设计要点)
- [6. 可扩展性设计](#6-可扩展性设计)
- [7. 目录结构](#7-目录结构)

---

## 1. 总体架构概览

```
┌──────────────────────────────────────────────────────────────────┐
│                     Client (Facade)                              │
│                                                                  │
│  createOrder() ──→ authorize() ──→ selfTest() ──→ validate()     │
│                                         ↓                        │
│                                   getCertificate()               │
│                                                                  │
│  (内部管理: 目录发现 · Nonce 缓存 · JWS/JWK 签名 · 账户注册           │
│             · 状态轮询 · HTTP 请求重试)                             │
└──────────┬───────────────────────┬───────────────────────────────┘
           │                       │
           ▼                       ▼
┌──────────────────┐    ┌─────────────────────────┐
│  Data\* (DTOs)   │    │  Helper (静态工具类)     │
│                  │    │                         │
│  Account         │    │  toDer()                │
│  Order           │    │  toSafeString()         │
│  Authorization   │    │  getNewKey()            │
│  Challenge       │    │  getNewECKey()          │
│  Certificate     │    │  getCsr()               │
│  File            │    │  splitCertificate()     │
│  Record          │    │  getCertExpiryDate()    │
│                  │    │  getKeyDetails()        │
└──────────────────┘    └─────────────────────────┘
           │                       │
           │                       ▼
           │              ┌─────────────────┐
           │              │  OpenSSL        │
           │              │  (密钥/CSR/签名) │
           │              └─────────────────┘
           │
           ▼
┌──────────────────────┐
│  外部依赖（注入）       │
│                      │
│  Flysystem\Filesystem│  ← 存储账户密钥
│  GuzzleHttp\Client   │  ← ACME API 通信
│  GuzzleHttp\Client   │  ← 自测 HTTP 抓取
│  GuzzleHttp\Client   │  ← Cloudflare DoH DNS 查询
└──────────────────────┘
```

### 分层说明

| 层次 | 组件 | 职责 |
|------|------|------|
| **外观层** | `Client` | 对外暴露证书签发 API，封装所有协议细节 |
| **数据层** | `Data\*` | ACME API 响应的类型安全 DTO |
| **工具层** | `Helper` | 静态方法：密钥生成、CSR 创建、PEM/DER 转换、证书拆分 |
| **基础设施** | Flysystem, GuzzleHttp, OpenSSL | 文件存储、HTTP 通信、加密操作 |

---

## 2. 设计模式分析

### 2.1 Facade（外观模式）— 主导模式

**文件**：`src/Client.php`

**意图**：为 ACME V2 协议提供一个统一的、简化的接口，隐藏子系统的复杂性。

**隐藏的子系统**：

| 子系统 | 隐藏细节 |
|--------|----------|
| ACME 目录发现 | 自动请求 `/directory` 获取端点映射 |
| Nonce 管理 | 从响应头缓存 `replay-nonce`，用完自动 HEAD 请求获取新 nonce |
| JWS 签名 | 根据场景自动选择 `signPayloadJWK()`（账户创建）或 `signPayloadKid()`（后续请求） |
| 账户生命周期 | 自动加载/生成 RSA 4096 账户密钥，自动同意 ToS |
| 状态轮询 | `validate()` 中循环轮询挑战状态直到 `valid` 或超时 |
| 证书链处理 | 自动拆分 domain cert + intermediate cert |

**对外 API**：

```php
// 用户只需调用 5 个方法即可完成证书签发
$order   = $client->createOrder(['example.org', 'www.example.org']);
$auths   = $client->authorize($order);
$client->selfTest($auths[0], Client::VALIDATION_HTTP);
$client->validate($auths[0]->getHttpChallenge());
$cert    = $client->getCertificate($order);
```

**关键实现**：

```php
// Client 构造函数自动完成初始化
public function __construct($config = [])
{
    $this->filesystem = $this->getOption('fs');   // 注入文件系统
    $this->init();                                  // 目录发现 + 密钥加载 + ToS 同意
}
```

---

### 2.2 DTO（数据传输对象）

**目录**：`src/Data/`

**意图**：将 ACME API 的 JSON 响应解码为类型安全、有明确语义的数据对象，在层间传递数据而不携带业务逻辑。

**DTO 一览**：

| DTO | 构造参数 | 用途 |
|-----|----------|------|
| `Account` | createdAt, isValid, accountURL | LE 账户信息，从 `newAccount` 响应构建 |
| `Order` | domains, url, status, expiresAt, identifiers, authorizations, finalizeURL | O订单，从 `newOrder` 响应构建 |
| `Authorization` | domain, expires, digest | 域名授权，从订单的 authorizations 端点响应构建 |
| `Challenge` | authorizationURL, type, status, url, token | HTTP-01 或 DNS-01 验证挑战 |
| `Certificate` | privateKey, csr, chain | 最终证书（含私钥、CSR、链） |
| `File` | filename, contents | HTTP-01 验证所需的文件（.well-known/acme-challenge/） |
| `Record` | name, value | DNS-01 验证所需的 TXT 记录（_acme-challenge. 前缀） |

**设计特征**：

- **构造注入**：所有属性通过构造函数一次性注入
- **只读访问**：仅暴露 getter，无 setter，确保对象不可变（`Authorization::addChallenge()` 是唯一例外）
- **类型约束**：PHP 8.3 强类型声明（`string`, `bool`, `array`, `\DateTime`）
- **零业务逻辑**：纯粹的 getter 透传，无计算逻辑（除 `Authorization` 的 `getFile()` 和 `getTxtRecord()` 外）

---

### 2.3 依赖注入（DI）

**注入方式**：通过 `Client` 构造函数的 `$config` 数组注入。

```php
$adapter = new LocalFilesystemAdapter('data');
$filesystem = new Filesystem($adapter);

$client = new Client([
    'username' => 'admin@example.org',
    'fs'       => $filesystem,         // 注入 Flysystem
    'mode'     => Client::MODE_STAGING, // 或 MODE_LIVE
    'source_ip' => '0.0.0.0',          // 可选：绑定源 IP
    'basePath' => 'le',                // 可选：账户密钥存储路径
    'key_length' => 4096,              // 可选：RSA 密钥位数
]);
```

**注入目标**：

| 依赖 | 注入方式 | 可替换性 |
|------|----------|----------|
| `League\Flysystem\Filesystem` | 显式注入（必选） | ✅ 支持 Local / S3 / Memory 等任意适配器 |
| `GuzzleHttp\Client` | 内部创建（可选配置透传） | ❌ 硬编码创建（但配置通过 `source_ip` 传入） |
| 自测 HTTP Client | 内部创建 | ❌ 硬编码创建 |
| 自测 DNS Client | 内部创建 | ❌ 硬编码创建（Cloudflare DoH） |

**优点**：存储层完全解耦，用户可自由选择文件存储后端。

---

### 2.4 策略模式（轻量实现）

**位置**：`Client::selfTest()`

**意图**：根据验证类型（HTTP-01 / DNS-01）选择不同的自测算法。

```php
public function selfTest(Authorization $authorization, $type = self::VALIDATION_HTTP, $maxAttempts = 15): bool
{
    if ($type == self::VALIDATION_HTTP) {
        return $this->selfHttpTest($authorization, $maxAttempts);  // 抓取 /.well-known/acme-challenge/
    } elseif ($type == self::VALIDATION_DNS) {
        return $this->selfDNSTest($authorization, $maxAttempts);   // 查询 Cloudflare DoH TXT 记录
    }
    return false;
}
```

| 策略 | 私有方法 | 验证方式 |
|------|----------|----------|
| HTTP-01 | `selfHttpTest()` | 发送 GET 到 `http://{domain}/.well-known/acme-challenge/{filename}`，比对返回内容 |
| DNS-01 | `selfDNSTest()` | 发送 DNS TXT 查询到 `https://cloudflare-dns.com/dns-query`，比对 `_acme-challenge.{domain}` 的记录值 |

**当前实现的局限**：使用 `if/else` 而非多态。若要扩展新的验证类型（如 TLS-ALPN-01），需要修改 `selfTest()` 方法。

---

## 3. 类职责矩阵

| 类 | 职责 | 依赖 | 是否可测试 |
|----|------|------|-----------|
| `Client` | ACME 协议编排、HTTP 通信、JWS 签名 | GuzzleHttp, Flysystem, Helper | 需要 mock HTTP 和文件系统 |
| `Helper` | 密钥生成、CSR 创建、格式转换 | OpenSSL | 可直接测试（纯静态方法） |
| `Data\Account` | 账户数据容器 | 无 | 可直接测试 |
| `Data\Order` | 订单数据容器 | 无 | 可直接测试 |
| `Data\Authorization` | 授权 + 挑战聚合 | Client (常量引用) | 可直接测试 |
| `Data\Challenge` | 挑战数据容器 | 无 | 可直接测试 |
| `Data\Certificate` | 证书数据容器 + 链拆分 | Helper | 可直接测试 |
| `Data\File` | HTTP 验证文件数据 | 无 | 可直接测试 |
| `Data\Record` | DNS TXT 记录数据 | 无 | 可直接测试 |

---

## 4. 数据流：证书签发生命周期

```
┌───────────────────────────────────────────────────────────────────────┐
│  Client 证书签发全流程                                                │
│                                                                       │
│  用户代码            Client 内部                                      │
│  ────────            ───────────                                      │
│                                                                       │
│  1. new Client()  →  ├─ GET /directory          （发现端点）           │
│                       ├─ 加载/生成 account.pem   （RSA 4096 密钥）    │
│                       ├─ POST newAccount         （注册 + 同意 ToS）  │
│                       └─ GET account             （获取账户信息）     │
│                                                                       │
│  2. createOrder()  →  POST newOrder {identifiers}                    │
│                       ← Order (含 authorizations URL 列表)            │
│                                                                       │
│  3. authorize()    →  GET {authorizationURL} × N                     │
│                       ← Authorization[] (各含 Challenge[])            │
│                                                                       │
│  4. selfTest()     →  ├─ HTTP: GET /.well-known/acme-challenge/{token}│
│                       └─ DNS:  Cloudflare DoH TXT 查询               │
│                                                                       │
│  5. validate()     →  POST {challengeURL} (keyAuthorization)          │
│                       └─ 轮询 GET {authorizationURL} 直到 valid       │
│                                                                       │
│  6. getCertificate()→  ├─ 生成 EC P-384 密钥                          │
│                       ├─ 创建 CSR (SAN 包含所有域名)                   │
│                       ├─ POST {finalizeURL} {csr}                     │
│                       └─ GET {certificateURL}                         │
│                       ← Certificate (私钥 + CSR + 证书链)             │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

### Nonce 管理流程

```
请求前 ──→ nonce 已缓存？ ──是──→ 使用缓存的 nonce
              │
              否
              │
              ▼
          HEAD {newNonce} ──→ 从响应头获取 replay-nonce
              │
              ▼
          构建 JWS 信封
              │
              ▼
          发送 POST 请求 ──→ 从响应头缓存新的 replay-nonce
```

---

## 5. 安全设计要点

| 方面 | 实现 |
|------|------|
| **账户密钥** | RSA 4096 位，通过 Flysystem 持久化，路径 `{basePath}/{user}/account.pem` |
| **CSR 密钥** | EC P-384 (secp384r1)，每次 `getCertificate()` 重新生成，不持久化 |
| **JWS 签名** | RS256（RSA-SHA256），使用 OpenSSL 原生签名，nonce 防重放 |
| **Nonce 管理** | 每次请求后从响应头 `replay-nonce` 更新缓存，用完自动 HEAD 请求获取 |
| **目录安全** | 仅存储账户密钥，证书和 CSR 密钥不落盘（由调用方决定是否持久化） |
| **证书链校验** | 自动拆分 domain cert 和 intermediate cert，提供 `getExpiryDate()` |

---

## 6. 可扩展性设计

### 当前支持的扩展点

| 扩展点 | 机制 | 示例 |
|--------|------|------|
| 存储后端 | 注入 Flysystem 适配器 | Local / S3 / Memory / FTP |
| ACME 环境 | `mode` 参数 | `MODE_LIVE` / `MODE_STAGING` |
| 源 IP 绑定 | `source_ip` 配置 | 多 IP 服务器指定出口 IP |
| 自测策略 | `selfTest()` 的 `$type` 参数 | HTTP-01 / DNS-01 |

### 潜在的扩展点

| 扩展方向 | 建议做法 |
|----------|----------|
| 新增验证类型 (TLS-ALPN-01) | 在 `selfTest()` 中新增分支，或在 `Challenge` 中增加类型判断 |
| 自定义 DNS 自测提供方 | 将 Cloudflare DoH url 改为可配置，或抽象为 `DnsResolverInterface` |
| 缓存策略 | 可对 `replay-nonce`、目录端点做缓存（当前无缓存） |
| 事件/钩子 | 在证书签发各阶段加入事件回调（如 `onBeforeValidate`, `onCertificateReady`） |

---

## 7. 目录结构

```
src/
├── Client.php              # Facade：ACME 协议编排入口
├── Helper.php              # 静态工具方法（密钥/CSR/格式转换）
└── Data/
    ├── Account.php         # 账户 DTO
    ├── Authorization.php   # 域名授权 DTO（含挑战聚合）
    ├── Certificate.php     # 证书 DTO（含链拆分）
    ├── Challenge.php       # 验证挑战 DTO
    ├── File.php            # HTTP-01 文件 DTO
    ├── Order.php           # 订单 DTO
    └── Record.php          # DNS TXT 记录 DTO
```

---

*文档版本：1.0 | 最后更新：2025 年*
