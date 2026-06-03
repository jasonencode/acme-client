<?php

namespace Jason\Acme\Data;

class Account
{
    /**
     * LE 账户创建时间
     * 由 LE API 返回的 createdAt 字段解析而来
     * @var \DateTime
     */
    protected \DateTime $createdAt;

    /**
     * 账户是否有效
     * true = status == 'valid'，表示账户已激活可用
     * @var bool
     */
    protected bool $isValid;

    /**
     * 账户在 LE 的唯一 URL
     * 用于 KID 模式 JWS 签名的 kid 字段，标识签名者身份
     * 同时也通过末尾数字 ID 作为账户标识
     * @var string
     */
    protected string $accountURL;

    /**
     * Account 构造函数
     *
     * @param \DateTime $createdAt  账户创建时间（从 LE API 响应中的 createdAt 解析而来）
     * @param bool      $isValid    账户是否有效（status == 'valid'）
     * @param string    $accountURL 账户在 LE 的唯一 URL（从响应头 Location 取得）
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
     * 从 account URL 中提取末尾数字作为账户 ID
     * 用于拼接订单请求 URL：/order/{accountId}/{orderId}
     *
     * @return string 账户数字 ID
     */
    public function getId(): string
    {
        return substr($this->accountURL, strrpos($this->accountURL, '/') + 1);
    }

    /**
     * 返回账户创建时间
     * 用于判断账户是已有账户还是本次新建的
     *
     * @return \DateTime
     */
    public function getCreatedAt(): \DateTime
    {
        return $this->createdAt;
    }

    /**
     * 返回账户 URL
     * 用于 KID 模式签名的 kid 字段
     *
     * @return string
     */
    public function getAccountURL(): string
    {
        return $this->accountURL;
    }

    /**
     * 返回账户是否有效
     * 仅在 status == 'valid' 时返回 true
     *
     * @return bool
     */
    public function isValid(): bool
    {
        return $this->isValid;
    }
}
