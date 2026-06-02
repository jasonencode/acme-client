<?php

namespace Jason\Acme\Data;

class Record
{

    /**
     * @var string
     */
    protected $name;

    /**
     * @var string
     */
    protected $value;

    /**
     * Record 构造函数
     * @param string $name
     * @param string $value
     */
    public function __construct(string $name, string $value)
    {
        $this->name = $name;
        $this->value = $value;
    }

    /**
     * 返回用于验证的 DNS TXT 记录名称
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * 返回 DNS 验证的记录值
     * @return string
     */
    public function getValue(): string
    {
        return $this->value;
    }
}
