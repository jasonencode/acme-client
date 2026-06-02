<?php

namespace Jason\Acme\Data;

use Jason\Acme\Client;
use Jason\Acme\Helper;

class Authorization
{

    /**
     * @var string
     */
    protected $domain;

    /**
     * @var \DateTime
     */
    protected $expires;

    /**
     * @var Challenge[]
     */
    protected $challenges = [];

    /**
     * @var string
     */
    protected $digest;

    /**
     * Authorization 构造函数
     * @param string $domain
     * @param string $expires
     * @param string $digest
     * @throws \Exception
     */
    public function __construct(string $domain, string $expires, string $digest)
    {
        $this->domain = $domain;
        $this->expires = (new \DateTime())->setTimestamp(strtotime($expires));
        $this->digest = $digest;
    }

    /**
     * 向授权添加验证挑战
     * @param Challenge $challenge
     */
    public function addChallenge(Challenge $challenge)
    {
        $this->challenges[] = $challenge;
    }

    /**
     * 返回正在授权的域名
     * @return string
     */
    public function getDomain(): string
    {
        return $this->domain;
    }


    /**
     * 返回授权的过期时间
     * @return \DateTime
     */
    public function getExpires(): \DateTime
    {
        return $this->expires;
    }

    /**
     * 返回验证挑战数组
     * @return Challenge[]
     */
    public function getChallenges(): array
    {
        return $this->challenges;
    }

    /**
     * 返回 HTTP 验证挑战
     * @return Challenge|bool
     */
    public function getHttpChallenge()
    {
        foreach ($this->getChallenges() as $challenge) {
            if ($challenge->getType() == Client::VALIDATION_HTTP) {
                return $challenge;
            }
        }

        return false;
    }

    /**
     * @return Challenge|bool
     */
    public function getDnsChallenge()
    {
        foreach ($this->getChallenges() as $challenge) {
            if ($challenge->getType() == Client::VALIDATION_DNS) {
                return $challenge;
            }
        }

        return false;
    }

    /**
     * 返回给定验证挑战的 File 对象
     * @return File|bool
     */
    public function getFile()
    {
        $challenge = $this->getHttpChallenge();
        if ($challenge !== false) {
            return new File($challenge->getToken(), $challenge->getToken() . '.' . $this->digest);
        }
        return false;
    }

    /**
     * 返回 DNS 记录对象
     *
     * @return Record|bool
     */
    public function getTxtRecord()
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
