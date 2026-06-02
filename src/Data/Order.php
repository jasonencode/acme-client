<?php


namespace Jason\Acme\Data;

class Order
{

    /**
     * @var string
     */
    protected $url;

    /**
     * @var string
     */
    protected $status;

    /**
     * @var \DateTime
     */
    protected $expiresAt;

    /**
     * @var array
     */
    protected $identifiers;

    /**
     * @var array
     */
    protected $authorizations;

    /**
     * @var string
     */
    protected $finalizeURL;

    /**
     * @var array
     */
    protected $domains;

    /**
     * Order 构造函数
     * @param array $domains
     * @param string $url
     * @param string $status
     * @param string $expiresAt
     * @param array $identifiers
     * @param array $authorizations
     * @param string $finalizeURL
     * @throws \Exception
     */
    public function __construct(
        array $domains,
        string $url,
        string $status,
        string $expiresAt,
        array $identifiers,
        array $authorizations,
        string $finalizeURL
    ) {
        //处理微秒日期格式
        if (strpos($expiresAt, '.') !== false) {
            $expiresAt = substr($expiresAt, 0, strpos($expiresAt, '.')) . 'Z';
        }
        $this->domains = $domains;
        $this->url = $url;
        $this->status = $status;
        $this->expiresAt = (new \DateTime())->setTimestamp(strtotime($expiresAt));
        $this->identifiers = $identifiers;
        $this->authorizations = $authorizations;
        $this->finalizeURL = $finalizeURL;
    }


    /**
     * 返回订单编号
     * @return string
     */
    public function getId(): string
    {
        return substr($this->url, strrpos($this->url, '/') + 1);
    }

    /**
     * 返回订单 URL
     * @return string
     */
    public function getURL(): string
    {
        return $this->url;
    }

    /**
     * 返回订单的授权集合
     * @return string[]
     */
    public function getAuthorizationURLs(): array
    {
        return $this->authorizations;
    }

    /**
     * 返回订单状态
     * @return string
     */
    public function getStatus(): string
    {
        return $this->status;
    }

    /**
     * 返回过期时间
     * @return \DateTime
     */
    public function getExpiresAt(): \DateTime
    {
        return $this->expiresAt;
    }

    /**
     * 返回域名标识符
     * @return array
     */
    public function getIdentifiers(): array
    {
        return $this->identifiers;
    }

    /**
     * 返回完成 URL
     * @return string
     */
    public function getFinalizeURL(): string
    {
        return $this->finalizeURL;
    }

    /**
     * 返回订单的域名列表
     * @return array
     */
    public function getDomains(): array
    {
        return $this->domains;
    }
}
