<?php


namespace Jason\Acme\Data;

class Order
{
    /**
     * 订单在 LE 的唯一 URL
     * 用于状态查询和标识订单
     * @var string
     */
    protected string $url;

    /**
     * 订单当前状态
     * pending（待验证）→ ready（可签发）→ processing（签发中）→ valid（完成）
     * @var string
     */
    protected string $status;

    /**
     * 订单过期时间
     * 超过此时间订单仍未完成则失效，需重新创建
     * @var \DateTime
     */
    protected \DateTime $expiresAt;

    /**
     * 订单中的域名标识符数组
     * 每个标识符包含 type（'dns'）和 value（域名）
     * @var array
     */
    protected array $identifiers;

    /**
     * 各域名的授权 URL 列表
     * 每个 URL 对应一个域名的 Authorization 对象
     * @var string[]
     */
    protected array $authorizations;

    /**
     * 最终化订单的 URL
     * 所有验证通过后，向此 URL 提交 CSR 以完成证书签发
     * @var string
     */
    protected string $finalizeURL;

    /**
     * 订单申请的域名列表
     * 第一个域名为主域名（commonName），其余为 SAN
     * @var string[]
     */
    protected array $domains;

    /**
     * Order 构造函数
     * 由 Client::createOrder() 或 Client::getOrder() 创建
     *
     * @param array  $domains       域名列表（第一个为主域名）
     * @param string $url           订单 URL
     * @param string $status        订单状态
     * @param string $expiresAt     过期时间（ISO 8601，含微秒则裁剪）
     * @param array  $identifiers   域名标识符列表
     * @param array  $authorizations 授权 URL 列表
     * @param string $finalizeURL   最终化 URL
     *
     * @throws \Exception 当时间格式解析失败时
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
     * 从订单 URL 提取末尾数字作为订单 ID
     * 用于通过 getOrder() 重新拉取订单
     *
     * @return string
     */
    public function getId(): string
    {
        return substr($this->url, strrpos($this->url, '/') + 1);
    }

    /**
     * 返回订单 URL
     *
     * @return string
     */
    public function getURL(): string
    {
        return $this->url;
    }

    /**
     * 返回授权 URL 列表
     * 每个 URL 对应 Client::authorize() 中的一个 Authorization
     *
     * @return string[]
     */
    public function getAuthorizationURLs(): array
    {
        return $this->authorizations;
    }

    /**
     * 返回订单状态
     * 'ready' 表示所有验证已通过，可进入证书签发
     *
     * @return string
     */
    public function getStatus(): string
    {
        return $this->status;
    }

    /**
     * 返回订单过期时间
     * 超时后需重新 createOrder()
     *
     * @return \DateTime
     */
    public function getExpiresAt(): \DateTime
    {
        return $this->expiresAt;
    }

    /**
     * 返回域名标识符数组
     * 每个元素包含 type（'dns'）和 value（域名）
     *
     * @return array
     */
    public function getIdentifiers(): array
    {
        return $this->identifiers;
    }

    /**
     * 返回最终化 URL
     * 所有域名验证通过后，向此 URL 提交 CSR 获取证书
     *
     * @return string
     */
    public function getFinalizeURL(): string
    {
        return $this->finalizeURL;
    }

    /**
     * 返回订单的域名列表
     * 第一个元素是主域名，其余是 SAN
     *
     * @return string[]
     */
    public function getDomains(): array
    {
        return $this->domains;
    }
}
