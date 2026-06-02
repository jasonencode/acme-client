# acme-client - ACME 客户端

基于 ACME V2 协议的 Let's Encrypt 客户端，与文件系统和 Web 服务器解耦，仅返回证书数据。

## 系统要求

- PHP8.3+
- openssl
- Flysystem

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

$adapter = new LocalFilesystemAdapter('data');
$filesystem = new Filesystem($adapter);

$client = new Client([
    'username' => 'example@example.org',
    'fs'       => $filesystem,
    'mode'     => Client::MODE_STAGING, // 或 MODE_LIVE
]);
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
