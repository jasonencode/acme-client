# acme-client - ACME 客户端

基于 ACME V2 协议的证书客户端，支持 Let's Encrypt 和 ZeroSSL，与文件系统和 Web 服务器解耦，仅返回证书数据。

## 系统要求

- PHP 8.3+
- OpenSSL 扩展
- Flysystem 3.x

## 安装

```bash
composer require jason/acme-client
```

## 快速开始

### 1. 实例化客户端

```php
use League\Flysystem\Filesystem;
use League\Flysystem\Local\LocalFilesystemAdapter;
use Jason\Acme\Client;
use Jason\Acme\ClientConfig;
use Jason\Acme\Enum\ClientMode;

$adapter = new LocalFilesystemAdapter('data');
$filesystem = new Filesystem($adapter);

// 使用 ClientConfig 配置客户端
$config = ClientConfig::create([
    'username' => 'example@example.org',
    'fs'       => $filesystem,
    'mode'     => ClientMode::STAGING, // 测试环境，正式使用时改为 ClientMode::LIVE
]);

$client = new Client($config);
```

### 2. 创建订单

```php
$order = $client->createOrder(['example.org', 'www.example.org']);
```

### 3. 获取授权

```php
$authorizations = $client->authorize($order);
```

### 4. 验证所有权

#### HTTP 验证
```php
foreach ($authorizations as $authorization) {
    $file = $authorization->getFile();
    file_put_contents($file->getFilename(), $file->getContents());
}
```

#### DNS 验证
```php
foreach ($authorizations as $authorization) {
    $txtRecord = $authorization->getTxtRecord();
    // $txtRecord->getName() 和 $txtRecord->getValue()
}
```

### 5. 自测

```php
// HTTP
if (!$client->selfTest($authorization, Client::VALIDATION_HTTP)) {
    throw new \Exception('验证失败');
}

// DNS
if (!$client->selfTest($authorization, Client::VALIDATION_DNS)) {
    throw new \Exception('验证失败');
}
sleep(30); // DNS 传播等待
```

### 6. 请求验证

```php
// HTTP
foreach ($authorizations as $authorization) {
    $client->validate($authorization->getHttpChallenge(), 15);
}

// DNS
foreach ($authorizations as $authorization) {
    $client->validate($authorization->getDnsChallenge(), 15);
}
```

### 7. 获取证书

```php
if ($client->isReady($order)) {
    $certificate = $client->getCertificate($order);
    
    file_put_contents('certificate.cert', $certificate->getCertificate());
    file_put_contents('private.key', $certificate->getPrivateKey());
    
    // 分别获取
    $domainCert = $certificate->getCertificate(false);
    $intermediateCert = $certificate->getIntermediate();
}
```

## 配置选项

### 完整配置示例

```php
use Jason\Acme\Client;
use Jason\Acme\ClientConfig;
use Jason\Acme\Enum\CertificateAuthority;
use Jason\Acme\Enum\ClientMode;
use Jason\Acme\Enum\KeyType;
use League\Flysystem\Filesystem;
use League\Flysystem\Local\LocalFilesystemAdapter;

$adapter = new LocalFilesystemAdapter('data');
$filesystem = new Filesystem($adapter);

// 方式 1：数组配置（推荐）
$client = new Client([
    'username'  => 'example@example.org',
    'fs'        => $filesystem,
    'mode'      => ClientMode::LIVE,
    'ca'        => CertificateAuthority::LETS_ENCRYPT,
    'key_type'  => KeyType::EC_384,
    'basePath'  => 'le',
    'source_ip' => '192.168.1.100',
]);

// 方式 2：使用 ClientConfig 类（高级配置）
$config = ClientConfig::create([
    'username' => 'example@example.org',
    'fs'       => $filesystem,
    'mode'     => ClientMode::STAGING,
    'ca'       => CertificateAuthority::ZERO_SSL,
    'key_type' => KeyType::RSA_4096,
]);
$client = new Client($config);
```

### 配置参数说明

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `username` | string | 否 | null | 邮箱地址，用于接收证书到期提醒 |
| `fs` | Filesystem | 是 | - | Flysystem 文件系统实例 |
| `mode` | ClientMode | 否 | `ClientMode::STAGING` | 运行模式 |
| `ca` | CertificateAuthority | 否 | `CertificateAuthority::LETS_ENCRYPT` | 证书颁发机构 |
| `key_type` | KeyType | 否 | `KeyType::EC_384` | 密钥类型 |
| `basePath` | string | 否 | `le` | 存储账户密钥和订单数据的目录 |
| `source_ip` | string | 否 | null | 绑定特定的出口 IP 地址 |

## 支持的证书颁发机构（CA）

### Let's Encrypt（默认）
```php
use Jason\Acme\Enum\CertificateAuthority;

$client = new Client([
    'fs' => $filesystem,
    'ca' => CertificateAuthority::LETS_ENCRYPT,
]);
```

### ZeroSSL
```php
use Jason\Acme\Enum\CertificateAuthority;

$client = new Client([
    'fs' => $filesystem,
    'ca' => CertificateAuthority::ZERO_SSL,
]);
```

### CA 对比

| CA | 标识符 | 免费 | 测试环境 | 说明 |
|----|--------|------|----------|------|
| Let's Encrypt | `CertificateAuthority::LETS_ENCRYPT` | ✅ | ✅ | 开源免费，全球广泛使用 |
| ZeroSSL | `CertificateAuthority::ZERO_SSL` | ✅ | ✅ | 提供免费和付费证书 |

## 密钥类型配置

### EC 密钥（推荐）

EC（椭圆曲线）密钥更小、更快，安全性更高，是 ACME 协议推荐的密钥类型。

```php
use Jason\Acme\Enum\KeyType;

// 使用 EC P-384（默认）
$client = new Client([
    'fs'       => $filesystem,
    'key_type' => KeyType::EC_384,
]);

// 使用 EC P-256
$client = new Client([
    'fs'       => $filesystem,
    'key_type' => KeyType::EC_256,
]);
```

### RSA 密钥

兼容性更好，适合旧版系统。

```php
use Jason\Acme\Enum\KeyType;

// 使用 RSA 4096
$client = new Client([
    'fs'       => $filesystem,
    'key_type' => KeyType::RSA_4096,
]);

// 使用 RSA 2048
$client = new Client([
    'fs'       => $filesystem,
    'key_type' => KeyType::RSA_2048,
]);
```

### 密钥类型对比

| 类型 | 标识符 | 安全强度 | 密钥大小 | 性能 |
|------|--------|----------|----------|------|
| EC P-256 | `KeyType::EC_256` | 128-bit | 较小 | 最快 |
| EC P-384 | `KeyType::EC_384` | 192-bit | 中等 | 快 |
| RSA 2048 | `KeyType::RSA_2048` | 112-bit | 大 | 较慢 |
| RSA 3072 | `KeyType::RSA_3072` | 128-bit | 较大 | 慢 |
| RSA 4096 | `KeyType::RSA_4096` | 192-bit | 很大 | 最慢 |

## 使用 ClientConfig 类

ClientConfig 提供更强大的配置管理、参数校验和类型安全保障，是推荐的配置方式。

### 创建配置

```php
use Jason\Acme\ClientConfig;
use Jason\Acme\Enum\CertificateAuthority;
use Jason\Acme\Enum\ClientMode;
use Jason\Acme\Enum\KeyType;
use League\Flysystem\Filesystem;

// 方式 1：使用静态工厂方法（推荐）
$config = ClientConfig::create([
    'username' => 'user@example.com',
    'fs'       => $filesystem,
    'mode'     => ClientMode::LIVE,
    'ca'       => CertificateAuthority::LETS_ENCRYPT,
    'key_type' => KeyType::EC_384,
]);

// 方式 2：直接实例化
$config = new ClientConfig([
    'fs'   => $filesystem,
    'mode' => ClientMode::STAGING,
]);

// 方式 3：空实例化后链式配置
$config = new ClientConfig();
$config->setFilesystem($filesystem)
       ->setMode(ClientMode::LIVE)
       ->setUsername('user@example.com');
```

### 链式配置方法

ClientConfig 支持流畅的链式调用：

```php
$config = new ClientConfig(['fs' => $filesystem]);

$config->setMode(ClientMode::LIVE)
       ->setUsername('admin@example.com')
       ->setCa(CertificateAuthority::ZERO_SSL)
       ->setKeyType(KeyType::RSA_4096)
       ->setBasePath('ssl')
       ->setSourceIp('192.168.1.100');
```

### 获取配置值

```php
$config->getMode();        // ClientMode::LIVE
$config->getCa();          // CertificateAuthority::ZERO_SSL
$config->getKeyType();     // KeyType::EC_384
$config->getUsername();    // 'admin@example.com'
$config->getFilesystem();  // Filesystem 实例
$config->getBasePath();    // 'ssl'
$config->getSourceIp();    // '192.168.1.100'
```

### 配置校验

ClientConfig 会自动进行参数校验，确保配置的有效性：

```php
try {
    $config = ClientConfig::create([
        'fs'   => $filesystem,
        'mode' => 'invalid', // 错误：必须是 ClientMode 枚举
    ]);
} catch (\InvalidArgumentException $e) {
    // 配置无效时抛出异常
    echo $e->getMessage();
}

// 手动校验（通常不需要，创建时自动校验）
$config->validate();
```

### 转换为数组

```php
$array = $config->toArray();
// 返回:
// [
//     'mode' => 'live',
//     'ca' => 'lets_encrypt',
//     'key_type' => 'ec_384',
//     'username' => 'admin@example.com',
//     'basePath' => 'ssl',
//     'source_ip' => '192.168.1.100',
// ]
```

## 静态工厂方法

ClientConfig 提供便捷的静态方法快速创建常用配置：

```php
// 创建生产环境配置
$config = ClientConfig::createLive($filesystem, 'admin@example.com');
// 等效于：
// ClientConfig::create([
//     'fs'       => $filesystem,
//     'username' => 'admin@example.com',
//     'mode'     => ClientMode::LIVE,
// ])

// 创建测试环境配置
$config = ClientConfig::createStaging($filesystem);
// 等效于：
// ClientConfig::create([
//     'fs'   => $filesystem,
//     'mode' => ClientMode::STAGING,
// ])

// 创建 ZeroSSL 配置
$config = ClientConfig::createZeroSSL($filesystem, 'admin@example.com');
// 等效于：
// ClientConfig::create([
//     'fs'       => $filesystem,
//     'username' => 'admin@example.com',
//     'mode'     => ClientMode::LIVE,
//     'ca'       => CertificateAuthority::ZERO_SSL,
// ])
```

## ClientConfig 方法参考

### 设置方法

| 方法 | 参数类型 | 说明 |
|------|----------|------|
| `setFilesystem(Filesystem $fs)` | `Filesystem` | 设置文件系统实例（必需） |
| `setMode(ClientMode $mode)` | `ClientMode` | 设置运行模式 |
| `setCa(CertificateAuthority $ca)` | `CertificateAuthority` | 设置证书颁发机构 |
| `setKeyType(KeyType $keyType)` | `KeyType` | 设置密钥类型 |
| `setUsername(?string $username)` | `string|null` | 设置邮箱地址 |
| `setBasePath(string $basePath)` | `string` | 设置存储基础路径 |
| `setSourceIp(?string $sourceIp)` | `string|null` | 设置出口 IP 地址 |

### 获取方法

| 方法 | 返回类型 | 说明 |
|------|----------|------|
| `getFilesystem()` | `Filesystem` | 获取文件系统实例 |
| `getMode()` | `ClientMode` | 获取运行模式 |
| `getCa()` | `CertificateAuthority` | 获取证书颁发机构 |
| `getKeyType()` | `KeyType` | 获取密钥类型 |
| `getUsername()` | `string|null` | 获取邮箱地址 |
| `getBasePath()` | `string` | 获取存储基础路径 |
| `getSourceIp()` | `string|null` | 获取出口 IP 地址 |

### 其他方法

| 方法 | 返回类型 | 说明 |
|------|----------|------|
| `validate()` | `void` | 校验配置有效性，无效时抛出异常 |
| `toArray()` | `array` | 转换为数组格式 |
| `create(array $config)` | `ClientConfig` | 静态工厂方法创建配置 |
| `createLive(Filesystem $fs, ?string $username = null)` | `ClientConfig` | 创建生产环境配置 |
| `createStaging(Filesystem $fs, ?string $username = null)` | `ClientConfig` | 创建测试环境配置 |
| `createZeroSSL(Filesystem $fs, ?string $username = null)` | `ClientConfig` | 创建 ZeroSSL 配置 |

## ClientConfig 最佳实践

### 1. 推荐使用静态工厂方法

```php
// ✅ 推荐
$config = ClientConfig::createLive($filesystem, 'admin@example.com');

// ❌ 不推荐（冗长）
$config = new ClientConfig();
$config->setFilesystem($filesystem);
$config->setMode(ClientMode::LIVE);
$config->setUsername('admin@example.com');
```

### 2. 配置复用

```php
// 创建基础配置
$baseConfig = ClientConfig::create([
    'fs'       => $filesystem,
    'username' => 'admin@example.com',
    'key_type' => KeyType::EC_384,
]);

// 创建生产环境客户端
$liveClient = new Client($baseConfig->setMode(ClientMode::LIVE));

// 创建测试环境客户端
$stagingClient = new Client($baseConfig->setMode(ClientMode::STAGING));
```

### 3. 类型安全

```php
// ✅ 正确（使用枚举类型）
$config->setMode(ClientMode::LIVE);

// ❌ 错误（不再支持字符串）
$config->setMode('live'); // 会抛出 TypeError
```

## 枚举类型参考

### ClientMode（运行模式）

```php
ClientMode::STAGING   // 测试环境
ClientMode::LIVE      // 生产环境
```

### CertificateAuthority（证书颁发机构）

```php
CertificateAuthority::LETS_ENCRYPT  // Let's Encrypt
CertificateAuthority::ZERO_SSL      // ZeroSSL
```

### KeyType（密钥类型）

```php
KeyType::EC_256      // EC P-256
KeyType::EC_384      // EC P-384（默认）
KeyType::RSA_2048    // RSA 2048
KeyType::RSA_3072    // RSA 3072
KeyType::RSA_4096    // RSA 4096
```

## 测试

```bash
# 运行所有测试
vendor/bin/phpunit

# 运行特定测试
vendor/bin/phpunit --filter HelperTest

# 代码静态分析
vendor/bin/phpstan analyse src --level=8
```

## 许可证

MIT License
