<?php

namespace Jason\Acme\Data;

class Challenge
{
    /**
     * 该挑战所属授权的 URL
     * 用于 validate() 中轮询授权状态
     * @var string
     */
    protected string $authorizationURL;

    /**
     * 挑战类型标识
     * 值为 'http-01' 或 'dns-01'
     * @var string
     */
    protected string $type;

    /**
     * 当前挑战状态
     * 可能值：pending（待验证）、processing（验证中）、valid（通过）、invalid（失败）
     * @var string
     */
    protected string $status;

    /**
     * 挑战验证 URL
     * 向此 URL 发送 POST 请求通知 LE 开始验证
     * @var string
     */
    protected string $url;

    /**
     * 挑战令牌
     * 用于拼接验证文件内容（HTTP-01）或 TXT 记录值（DNS-01）
     * @var string
     */
    protected string $token;

    /**
     * Challenge 构造函数
     * 由 Client::authorize() 从 LE 返回的 challenges 数组创建
     *
     * @param string $authorizationURL 所属授权的 URL
     * @param string $type             挑战类型（http-01/dns-01）
     * @param string $status           初始状态
     * @param string $url              验证请求 URL
     * @param string $token            挑战令牌
     */
    public function __construct(string $authorizationURL, string $type, string $status, string $url, string $token)
    {
        $this->authorizationURL = $authorizationURL;
        $this->type = $type;
        $this->status = $status;
        $this->url = $url;
        $this->token = $token;
    }

    /**
     * 返回挑战验证 URL
     * 向此 URL 发送 POST 请求即通知 LE 开始验证
     *
     * @return string
     */
    public function getUrl(): string
    {
        return $this->url;
    }

    /**
     * 返回挑战类型
     * 'http-01' 表示通过 HTTP 文件验证
     * 'dns-01' 表示通过 DNS 记录验证
     *
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * 返回挑战令牌
     * 用于构造 HTTP-01 验证文件名 或 DNS-01 的 TXT 记录值
     *
     * @return string
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * 返回挑战状态
     * 常用于 validate() 轮询后检查结果
     *
     * @return string
     */
    public function getStatus(): string
    {
        return $this->status;
    }

    /**
     * 返回挑战所属的授权 URL
     * 用于 validate() 轮询时请求授权接口查看验证结果
     *
     * @return string
     */
    public function getAuthorizationURL(): string
    {
        return $this->authorizationURL;
    }
}