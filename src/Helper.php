<?php

namespace Jason\Acme;

use Jason\Acme\Enum\KeyType;
use Jason\Acme\Exception\AcmeException;

/**
 * Helper 类
 * 包含证书处理的辅助方法
 * @package Jason\Acme
 */
class Helper
{
    /**
     * 将 PEM 格式的密钥转换为 DER 二进制格式
     *
     * ACME 协议中，JWS 签名时需将账户密钥以 DER 格式进行 digest 计算。
     * 该步骤位于密钥生成之后、JWK 指纹计算之前——先 toDer() 解码，再 toSafeString() 编码为 base64url。
     * PEM 是 base64 文本格式，DER 是原始二进制格式，此方法去除 PEM 头尾标记并解码。
     *
     * @param string $pem   PEM 格式的密钥字符串（含 -----BEGIN/END----- 标记）
     *
     * @return string DER 二进制原始数据
     * @throws \Exception 当 base64 解码失败时抛出
     */
    public static function toDer(string $pem): string
    {
        $lines = preg_split('/\n|\r\n?/', $pem);
        $lines = array_slice($lines, 1, -1);

        $result = base64_decode(implode('', $lines));
        if ($result === false) {
            throw new AcmeException('Could not decode PEM to DER');
        }

        return $result;
    }

    /**
     * 解析证书并返回过期日期
     *
     * 在 ACME 证书续期流程中，调用此方法检查已签发证书的 validTo 时间。
     * 上游：splitCertificate() 拆分后的域名证书作为输入；
     * 下游：调用方据此判断是否需要在证书到期前（通常提前 30 天）重新发起订单流程。
     *
     * @param string $certificate   PEM 格式的 X.509 证书字符串
     *
     * @return \DateTime 证书过期日期
     * @throws \Exception 当 openssl 无法解析证书时抛出
     */
    public static function getCertExpiryDate(string $certificate): \DateTime
    {
        $info = openssl_x509_parse($certificate);
        if ($info === false) {
            throw new AcmeException('Could not parse certificate');
        }
        $dateTime = new \DateTime();
        $dateTime->setTimestamp($info['validTo_time_t']);

        return $dateTime;
    }

    /**
     * 根据指定类型生成新密钥
     *
     * 支持 RSA 和 EC 两种密钥类型，用于 ACME 账户注册或证书请求。
     * 默认使用 EC P-384 密钥（ACME 协议推荐）。
     *
     * @param KeyType $type 密钥类型枚举
     *
     * @return string PEM 格式的私钥字符串
     * @throws \Exception 当密钥生成失败时抛出
     */
    public static function getNewKeyByType(KeyType $type = KeyType::EC_384): string
    {
        $openSSLType = $type->getOpenSSLType();
        $parameter = $type->getParameter();

        $config = [
            'private_key_type' => $openSSLType,
        ];

        if ($openSSLType === OPENSSL_KEYTYPE_EC) {
            $config['curve_name'] = $parameter;
        } else {
            $config['private_key_bits'] = $parameter;
        }

        $key = openssl_pkey_new($config);
        if ($key === false) {
            throw new AcmeException('Could not generate ' . $type->getLabel() . ' key');
        }

        if (openssl_pkey_export($key, $pem) === false) {
            throw new AcmeException('Could not export ' . $type->getLabel() . ' key as PEM');
        }

        return $pem;
    }

    /**
     * 生成 RSA 密钥对并返回 PEM 格式的私钥
     *
     * 兼容场景：部分 CA 或旧版系统不支持 EC 密钥时，使用 RSA 作为备选。
     * 此方法是 getNewKeyByType() 的便捷别名。
     *
     * @param int $keyLength RSA 密钥长度（bit），如 2048、4096（默认 4096）
     *
     * @return string PEM 格式的 RSA 私钥字符串
     * @throws \Exception 当 OpenSSL 密钥生成或导出失败时抛出
     */
    public static function getNewKey(int $keyLength = 4096): string
    {
        $keyType = match ($keyLength) {
            2048 => KeyType::RSA_2048,
            3072 => KeyType::RSA_3072,
            4096 => KeyType::RSA_4096,
            default => throw new AcmeException('Unsupported RSA key length: ' . $keyLength . '. Supported lengths: 2048, 3072, 4096'),
        };

        return self::getNewKeyByType($keyType);
    }

    /**
     * 创建证书签名请求（CSR）
     *
     * 在 ACME 订单（Order）流程的最后阶段调用，用于向 CA 提交域名列表以申请证书。
     * 上游：getNewECKey() 或 getNewKey() 生成的私钥作为签名密钥；
     *      $domains 数组包含需要保护的所有域名（主域名 + 附加域名 SAN）。
     * 下游：生成的 CSR PEM 字符串通过 Client::finalizeOrder() 提交给 ACME 服务端。
     * 内部生成临时 OpenSSL 配置文件以注入 subjectAltName（SAN）扩展，主域名设 commonName。
     *
     * @param array                    $domains  域名列表，第一个元素为主域名，其余为 SAN
     * @param \OpenSSLAsymmetricKey|string $key      用于签名 CSR 的私钥（PEM 字符串或 OpenSSL 资源）
     *
     * @return string PEM 格式的 CSR 字符串
     * @throws \Exception 当 CSR 创建或导出失败时抛出
     */
    public static function getCsr(array $domains, \OpenSSLAsymmetricKey|string $key): string
    {
        $primaryDomain = current(($domains));
        $config = [
            '[req]',
            'distinguished_name=req_distinguished_name',
            '[req_distinguished_name]',
            '[v3_req]',
            '[v3_ca]',
            '[SAN]',
            'subjectAltName=' . implode(',', array_map(function ($domain) {
                return 'DNS:' . $domain;
            }, $domains)),
        ];

        $fn = tempnam(sys_get_temp_dir(), md5(microtime(true)));
        file_put_contents($fn, implode("\n", $config));
        $csr = openssl_csr_new([
            'countryName' => 'NL',
            'commonName'  => $primaryDomain,
        ], $key, [
            'config'         => $fn,
            'req_extensions' => 'SAN',
            'digest_alg'     => 'sha512',
        ]);
        unlink($fn);

        if ($csr === false) {
            throw new AcmeException('Could not create a CSR');
        }

        if (openssl_csr_export($csr, $result) == false) {
            throw new AcmeException('CRS export failed');
        }

        $result = trim($result);

        return $result;
    }

    /**
     * 生成安全的 base64 字符串
     *
     * @param string $data
     *
     * @return string
     */
    public static function toSafeString(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * 获取密钥信息
     *
     * @param \OpenSSLAsymmetricKey $key
     *
     * @return array
     * @throws \Exception
     */
    public static function getKeyDetails(\OpenSSLAsymmetricKey $key): array
    {
        $accountDetails = openssl_pkey_get_details($key);
        if ($accountDetails === false) {
            throw new AcmeException('Could not load account details');
        }

        return $accountDetails;
    }

    /**
     * 将双证书包拆分为独立的多行字符串证书
     * @param string $chain
     * @return array
     * @throws \Exception
     */
    public static function splitCertificate(string $chain): array
    {
        preg_match(
            '/^(?<domain>-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----)\n'
            . '(?<intermediate>-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----)$/s',
            $chain,
            $certificates
        );

        $domain = $certificates['domain'] ?? null;
        $intermediate = $certificates['intermediate'] ?? null;

        if (!$domain || !$intermediate) {
            throw new AcmeException('Could not parse certificate string');
        }

        return [$domain, $intermediate];
    }
}
