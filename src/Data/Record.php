<?php

namespace Jason\Acme\Data;

class Record
{
    /**
     * DNS-01 验证的 TXT 记录名
     * 格式：'_acme-challenge.' + 域名
     * 如 '_acme-challenge.example.com'
     * @var string
     */
    protected string $name;

    /**
     * DNS-01 验证的 TXT 记录值
     * 格式：base64url(sha256(token + "." + digest))
     * @var string
     */
    protected string $value;

    /**
     * Record 构造函数
     * 由 Authorization::getTxtRecord() 创建
     *
     * @param string $name  DNS TXT 记录名（_acme-challenge.{domain}）
     * @param string $value TXT 记录值（base64url 编码）
     */
    public function __construct(string $name, string $value)
    {
        $this->name = $name;
        $this->value = $value;
    }

    /**
     * 返回 DNS TXT 记录名
     * 需将此记录添加到 DNS 配置中
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * 返回 DNS TXT 记录值
     * LE 查询 _acme-challenge.{domain} 时比对的值
     *
     * @return string
     */
    public function getValue(): string
    {
        return $this->value;
    }
}
