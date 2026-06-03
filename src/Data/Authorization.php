<?php

namespace Jason\Acme\Data;

use Jason\Acme\Client;
use Jason\Acme\Helper;

class Authorization
{
    /**
     * 正被授权的域名
     * 如 'example.com'，对应 Order 中 identifiers 的 value
     * @var string
     */
    protected string $domain;

    /**
     * 授权的过期时间
     * 超过此时间未完成验证则授权失效，需重新创建订单
     * @var \DateTime
     */
    protected \DateTime $expires;

    /**
     * 该域名的所有可用验证挑战
     * 通常至少包含 http-01 和 dns-01 两种类型
     * 由 analyze() 中遍历 LE 响应填充
     * @var Challenge[]
     */
    protected array $challenges = [];

    /**
     * 账户的 JWK Thumbprint
     * 由 Client::getDigest() 传入，用于构造验证文件内容或 TXT 记录值
     * @var string
     */
    protected string $digest;

    /**
     * Authorization 构造函数
     * 由 Client::authorize() 创建，传入域名、过期时间和密钥指纹
     *
     * @param string $domain  正被授权的域名
     * @param string $expires LE 返回的授权过期时间（ISO 8601 格式，如含微秒则裁剪）
     * @param string $digest  账户 JWK Thumbprint，用于拼接验证值
     * @param Challenge[] $challenges  验证挑战列表
     *
     * @throws \Exception 当时间格式解析失败时
     */
    public function __construct(string $domain, string $expires, string $digest, array $challenges = [])
    {
        $this->domain = $domain;
        $this->expires = (new \DateTime())->setTimestamp(strtotime($expires));
        $this->digest = $digest;
        $this->challenges = $challenges;
    }

    /**
     * 返回正在授权的域名
     * 用于自测时拼接 URL 或 DNS 查询名
     *
     * @return string
     */
    public function getDomain(): string
    {
        return $this->domain;
    }


    /**
     * 返回授权的过期时间
     * 超过此时间后授权失效，需重新创建订单
     *
     * @return \DateTime
     */
    public function getExpires(): \DateTime
    {
        return $this->expires;
    }

    /**
     * 返回该授权的所有验证挑战
     * 由 Client::validate() 或用户自行遍历使用
     *
     * @return Challenge[]
     */
    public function getChallenges(): array
    {
        return $this->challenges;
    }

    /**
     * 从挑战列表中查找 HTTP-01 类型的挑战
     * 由 getFile() 内部调用，也可由用户直接获取挑战对象
     *
     * @return Challenge|false 找到返回 Challenge，不存在返回 false
     */
    public function getHttpChallenge(): Challenge|false
    {
        foreach ($this->getChallenges() as $challenge) {
            if ($challenge->getType() == Client::VALIDATION_HTTP) {
                return $challenge;
            }
        }

        return false;
    }

    /**
     * 从挑战列表中查找 DNS-01 类型的挑战
     * 由 getTxtRecord() 内部调用，也可由用户直接获取挑战对象
     *
     * @return Challenge|false 找到返回 Challenge，不存在返回 false
     */
    public function getDnsChallenge(): Challenge|false
    {
        foreach ($this->getChallenges() as $challenge) {
            if ($challenge->getType() == Client::VALIDATION_DNS) {
                return $challenge;
            }
        }

        return false;
    }

    /**
     * 构造 HTTP-01 验证所需的文件 DTO
     * 文件名 = token，文件内容 = token + "." + digest
     * 用户需将此文件部署到 http://<domain>/.well-known/acme-challenge/{token}
     *
     * @return File|false 无 HTTP 挑战时返回 false
     */
    public function getFile(): File|false
    {
        $challenge = $this->getHttpChallenge();
        if ($challenge !== false) {
            return new File($challenge->getToken(), $challenge->getToken() . '.' . $this->digest);
        }
        return false;
    }

    /**
     * 构造 DNS-01 验证所需的 TXT 记录 DTO
     * 记录名 = '_acme-challenge.' + 域名，记录值 = base64url(sha256(token.digest))
     * 用户需将此记录添加到域名 DNS 配置中
     *
     * @return Record|false 无 DNS 挑战时返回 false
     */
    public function getTxtRecord(): Record|false
    {
        $challenge = $this->getDnsChallenge();
        if ($challenge !== false) {
            $hash = hash('sha256', $challenge->getToken() . '.' . $this->digest, true);
            $value = Helper::toSafeString($hash);
            return new Record('_acme-challenge.' . $this->getDomain(), $value);
        }

        return false;
    }
}
