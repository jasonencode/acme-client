<?php

namespace Jason\Acme\Data;

class Challenge
{

    /**
     * @var string
     */
    protected $authorizationURL;

    /**
     * @var string
     */
    protected $type;

    /**
     * @var string
     */
    protected $status;

    /**
     * @var string
     */
    protected $url;

    /**
     * @var string
     */
    protected $token;

    /**
     * Challenge 构造函数
     * @param string $authorizationURL
     * @param string $type
     * @param string $status
     * @param string $url
     * @param string $token
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
     * 获取验证挑战的 URL
     * @return string
     */
    public function getUrl(): string
    {
        return $this->url;
    }

    /**
     * 返回验证挑战类型（DNS 或 HTTP）
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * 返回令牌
     * @return string
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * 返回状态
     * @return string
     */
    public function getStatus(): string
    {
        return $this->status;
    }

    /**
     * 返回授权 URL
     * @return string
     */
    public function getAuthorizationURL(): string
    {
        return $this->authorizationURL;
    }
}
