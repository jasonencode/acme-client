<?php

namespace Jason\Acme\Data;

class Account
{
    /**
     * @var \DateTime
     */
    protected $createdAt;

    /**
     * @var bool
     */
    protected $isValid;

    /**
     * @var string
     */
    protected $accountURL;


    /**
     * Account 构造函数
     * @param \DateTime $createdAt
     * @param bool $isValid
     * @param string $accountURL
     */
    public function __construct(
        \DateTime $createdAt,
        bool $isValid,
        string $accountURL
    ) {
        $this->createdAt = $createdAt;
        $this->isValid = $isValid;
        $this->accountURL = $accountURL;
    }

    /**
     * 返回账户 ID
     * @return string
     */
    public function getId(): string
    {
        return substr($this->accountURL, strrpos($this->accountURL, '/') + 1);
    }

    /**
     * 返回账户创建日期
     * @return \DateTime
     */
    public function getCreatedAt(): \DateTime
    {
        return $this->createdAt;
    }

    /**
     * 返回账户 URL
     * @return string
     */
    public function getAccountURL(): string
    {
        return $this->accountURL;
    }

    /**
     * 返回验证状态
     * @return bool
     */
    public function isValid(): bool
    {
        return $this->isValid;
    }
}
