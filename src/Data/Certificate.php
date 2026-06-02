<?php

namespace Jason\Acme\Data;

use Jason\Acme\Helper;

class Certificate
{

    /**
     * @var string
     */
    protected $privateKey;

    /**
     * @var string
     */
    protected $chain;

    /**
     * @var string
     */
    protected $certificate;

    /**
     * @var string
     */
    protected $intermediateCertificate;

    /**
     * @var string
     */
    protected $csr;

    /**
     * @var \DateTime
     */
    protected $expiryDate;

    /**
     * Certificate 构造函数
     * @param $privateKey
     * @param $csr
     * @param $chain
     * @throws \Exception
     */
    public function __construct($privateKey, $csr, $chain)
    {
        $this->privateKey = $privateKey;
        $this->csr = $csr;
        $this->chain = $chain;
        list($this->certificate, $this->intermediateCertificate) = Helper::splitCertificate($chain);
        $this->expiryDate = Helper::getCertExpiryDate($chain);
    }

    /**
     * 获取证书签名请求（CSR）
     * @return string
     */
    public function getCsr(): string
    {
        return $this->csr;
    }

    /**
     * 获取当前证书的过期日期
     * @return \DateTime
     */
    public function getExpiryDate(): \DateTime
    {
        return $this->expiryDate;
    }

    /**
     * 以多行字符串形式返回证书，默认包含中间证书
     *
     * @param bool $asChain
     * @return string
     */
    public function getCertificate($asChain = true): string
    {
        return $asChain ? $this->chain : $this->certificate;
    }

    /**
     * 以多行字符串形式返回中间证书
     * @return string
     */
    public function getIntermediate(): string
    {
        return $this->intermediateCertificate;
    }

    /**
     * 以多行字符串形式返回私钥
     * @return string
     */
    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }
}
