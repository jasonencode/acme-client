<?php

namespace Jason\Acme\Enum;

/**
 * 密钥类型枚举
 * 
 * 支持多种密钥类型，用于 ACME 账户注册和证书请求。
 * 
 * @package Jason\Acme\Enum
 */
enum KeyType: string
{
    /**
     * EC P-256 曲线（secp256r1）
     * 128 位安全强度，密钥较小，性能较好
     */
    case EC_256 = 'ec_256';

    /**
     * EC P-384 曲线（secp384r1）
     * 192 位安全强度，ACME 协议推荐使用
     */
    case EC_384 = 'ec_384';

    /**
     * RSA 2048 位
     * 112 位安全强度，兼容性好，适合旧系统
     */
    case RSA_2048 = 'rsa_2048';

    /**
     * RSA 3072 位
     * 128 位安全强度，平衡安全性和性能
     */
    case RSA_3072 = 'rsa_3072';

    /**
     * RSA 4096 位
     * 192 位安全强度，最高安全级别
     */
    case RSA_4096 = 'rsa_4096';

    /**
     * 获取密钥显示名称
     *
     * @return string
     */
    public function getLabel(): string
    {
        return match ($this) {
            self::EC_256 => 'EC P-256',
            self::EC_384 => 'EC P-384',
            self::RSA_2048 => 'RSA 2048',
            self::RSA_3072 => 'RSA 3072',
            self::RSA_4096 => 'RSA 4096',
        };
    }

    /**
     * 获取 OpenSSL 参数
     *
     * @return string
     */
    public function getParameter(): string
    {
        return match ($this) {
            self::EC_256 => 'prime256v1',
            self::EC_384 => 'secp384r1',
            self::RSA_2048 => '2048',
            self::RSA_3072 => '3072',
            self::RSA_4096 => '4096',
        };
    }

    /**
     * 获取 OpenSSL 密钥类型常量
     *
     * @return int
     */
    public function getOpenSSLType(): int
    {
        return match ($this) {
            self::EC_256, self::EC_384 => OPENSSL_KEYTYPE_EC,
            self::RSA_2048, self::RSA_3072, self::RSA_4096 => OPENSSL_KEYTYPE_RSA,
        };
    }
}
