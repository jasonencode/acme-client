<?php

declare(strict_types=1);

namespace Jason\Acme\Tests\Unit\Data;

use Jason\Acme\Data\Account;
use PHPUnit\Framework\TestCase;

class AccountTest extends TestCase
{
    public function testGetId(): void
    {
        $date = new \DateTime();
        $account = new Account($date, true, 'https://acme-v02.api.letsencrypt.org/acme/acct/123456');
        
        $this->assertEquals('123456', $account->getId());
    }

    public function testGetIdWithLastSlash(): void
    {
        $date = new \DateTime();
        $account = new Account($date, true, 'https://acme-v02.api.letsencrypt.org/acme/acct/123456/');
        
        $this->assertEquals('', $account->getId());
    }

    public function testGetCreatedAt(): void
    {
        $date = new \DateTime('2024-01-01 12:00:00');
        $account = new Account($date, true, 'https://example.com/acct/123');
        
        $this->assertEquals($date, $account->getCreatedAt());
    }

    public function testGetAccountURL(): void
    {
        $date = new \DateTime();
        $accountURL = 'https://acme-v02.api.letsencrypt.org/acme/acct/123456';
        $account = new Account($date, true, $accountURL);
        
        $this->assertEquals($accountURL, $account->getAccountURL());
    }

    public function testIsValid(): void
    {
        $date = new \DateTime();
        
        $validAccount = new Account($date, true, 'https://example.com/acct/1');
        $invalidAccount = new Account($date, false, 'https://example.com/acct/2');
        
        $this->assertTrue($validAccount->isValid());
        $this->assertFalse($invalidAccount->isValid());
    }
}
