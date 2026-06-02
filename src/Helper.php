<?php

namespace Jason\Acme;

use GuzzleHttp\Exception\ClientException;

/**
 * Helper 类
 * 包含证书处理的辅助方法
 * @package Jason\Acme
 */
class Helper
{

    /**
     * 格式化转换器
     * @param $pem
     * @return false|string
     * @see https://eidson.info/post/php_eol_is_broken
     */
    public static function toDer($pem)
    {
        $lines = preg_split('/\n|\r\n?/', $pem);
        $lines = array_slice($lines, 1, -1);

        return base64_decode(implode('', $lines));
    }

    /**
     * 返回证书过期日期
     *
     * @param $certificate
     *
     * @return \DateTime
     * @throws \Exception
     */
    public static function getCertExpiryDate($certificate): \DateTime
    {
        $info = openssl_x509_parse($certificate);
        if ($info === false) {
            throw new \Exception('Could not parse certificate');
        }
        $dateTime = new \DateTime();
        $dateTime->setTimestamp($info['validTo_time_t']);

        return $dateTime;
    }

    public static function getNewECKey(): string
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'secp384r1',
        ]);
        openssl_pkey_export($key, $pem);

        return $pem;
    }

    /**
     * 获取新的 RSA 密钥
     *
     * @return string
     */
    public static function getNewKey(int $keyLength): string
    {
        $key = openssl_pkey_new([
            'private_key_bits' => $keyLength,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($key, $pem);

        return $pem;
    }

    /**
     * 获取新的证书签名请求（CSR）
     *
     * @param array $domains
     * @param       $key
     *
     * @return string
     * @throws \Exception
     */
    public static function getCsr(array $domains, $key): string
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
            throw new \Exception('Could not create a CSR');
        }

        if (openssl_csr_export($csr, $result) == false) {
            throw new \Exception('CRS export failed');
        }

        $result = trim($result);

        return $result;
    }

    /**
     * 生成安全的 base64 字符串
     *
     * @param $data
     *
     * @return string
     */
    public static function toSafeString($data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * 获取密钥信息
     *
     * @return array
     * @throws \Exception
     */
    public static function getKeyDetails($key): array
    {
        $accountDetails = openssl_pkey_get_details($key);
        if ($accountDetails === false) {
            throw new \Exception('Could not load account details');
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
            throw new \Exception('Could not parse certificate string');
        }

        return [$domain, $intermediate];
    }
}
