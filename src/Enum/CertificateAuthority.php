<?php

namespace Jason\Acme\Enum;

/**
 * ACME 证书颁发机构（CA）配置枚举
 * 
 * 支持多种 ACME 兼容的证书颁发机构
 * 
 * @package Jason\Acme\Enum
 */
enum CertificateAuthority: string
{
    /**
     * Let's Encrypt - 免费开源的证书颁发机构
     */
    case LETS_ENCRYPT = 'lets_encrypt';

    /**
     * ZeroSSL - 提供免费和付费 SSL 证书
     */
    case ZERO_SSL = 'zero_ssl';

    /**
     * 获取生产环境目录地址
     *
     * @return string
     */
    public function getProductionUrl(): string
    {
        return match ($this) {
            self::LETS_ENCRYPT => 'https://acme-v02.api.letsencrypt.org/directory',
            self::ZERO_SSL => 'https://acme.zerossl.com/v2/DV90',
        };
    }

    /**
     * 获取测试/暂存环境目录地址
     *
     * @return string|null 如果该 CA 没有测试环境则返回 null
     */
    public function getStagingUrl(): ?string
    {
        return match ($this) {
            self::LETS_ENCRYPT => 'https://acme-staging-v02.api.letsencrypt.org/directory',
            self::ZERO_SSL => 'https://acme.zerossl.com/v2/DV90/staging',
        };
    }

    /**
     * 获取 CA 显示名称
     *
     * @return string
     */
    public function getLabel(): string
    {
        return match ($this) {
            self::LETS_ENCRYPT => "Let's Encrypt",
            self::ZERO_SSL => 'ZeroSSL',
        };
    }

    /**
     * 根据环境获取目录地址
     *
     * @param ClientMode $mode
     *
     * @return string
     * @throws \InvalidArgumentException 如果指定了测试环境但该 CA 不支持
     */
    public function getDirectoryUrl(ClientMode $mode): string
    {
        if ($mode === ClientMode::STAGING) {
            $stagingUrl = $this->getStagingUrl();
            if ($stagingUrl === null) {
                throw new \InvalidArgumentException(
                    sprintf('%s does not support staging environment', $this->getLabel())
                );
            }
            return $stagingUrl;
        }

        return $this->getProductionUrl();
    }

}
