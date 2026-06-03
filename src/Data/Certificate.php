<?php

namespace Jason\Acme\Data;

use Jason\Acme\Helper;

class Certificate
{
    /**
     * 域名证书私钥（EC P-384，PEM 格式）
     * 由 getCertificate() 中 getNewECKey() 生成，用于创建 CSR
     * @var string
     */
    protected string $privateKey;

    /**
     * LE 返回的完整证书链（PEM 格式）
     * 包含域名证书和中间证书
     * @var string
     */
    protected string $chain;

    /**
     * 拆分后的域名证书（PEM 格式）
     * 由 splitCertificate() 从 chain 中提取
     * @var string
     */
    protected string $certificate;

    /**
     * 拆分后的中间证书（PEM 格式）
     * 由 splitCertificate() 从 chain 中提取
     * @var string
     */
    protected string $intermediateCertificate;

    /**
     * 提交给 LE 的证书签名请求（PEM 格式）
     * 用于记录和验证 CSR 内容
     * @var string
     */
    protected string $csr;

    /**
     * 证书过期日期
     * 由 getCertExpiryDate() 从域名证书中解析
     * 用于判断是否需要续期（通常提前 30 天）
     * @var \DateTime
     */
    protected \DateTime $expiryDate;

    /**
     * Certificate 构造函数
     * 自动调用 splitCertificate() 拆分证书链，getCertExpiryDate() 解析过期时间
     *
     * @param string $privateKey  EC P-384 私钥（PEM）
     * @param string $csr         证书签名请求（PEM）
     * @param string $chain       LE 返回的完整证书链（PEM，含域名证书 + 中间证书）
     *
     * @throws \Exception 当证书链解析失败时
     */
    public function __construct(string $privateKey, string $csr, string $chain)
    {
        $this->privateKey = $privateKey;
        $this->csr = $csr;
        $this->chain = $chain;
        list($this->certificate, $this->intermediateCertificate) = Helper::splitCertificate($chain);
        $this->expiryDate = Helper::getCertExpiryDate($chain);
    }

    /**
     * 返回原始 CSR 的 PEM 字符串
     * 用于存档或验证提交的 CSR 内容
     *
     * @return string
     */
    public function getCsr(): string
    {
        return $this->csr;
    }

    /**
     * 返回证书过期日期
     * 用于判断是否需要在到期前续期
     *
     * @return \DateTime
     */
    public function getExpiryDate(): \DateTime
    {
        return $this->expiryDate;
    }

    /**
     * 返回证书 PEM 字符串
     * 默认返回完整链（域名证书 + 中间证书），也可只返回域名证书
     *
     * @param bool $asChain true=返回完整链，false=只返回域名证书
     * @return string
     */
    public function getCertificate(bool $asChain = true): string
    {
        return $asChain ? $this->chain : $this->certificate;
    }

    /**
     * 返回中间证书的 PEM 字符串
     * Web 服务器配置中通常需要将域名证书与中间证书一起安装
     *
     * @return string
     */
    public function getIntermediate(): string
    {
        return $this->intermediateCertificate;
    }

    /**
     * 返回域名证书的 EC P-384 私钥（PEM 格式）
     * 用于配置 Web 服务器的 SSL/TLS
     *
     * @return string
     */
    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }
}
