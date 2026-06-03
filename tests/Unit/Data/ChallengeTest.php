<?php

declare(strict_types=1);

namespace Jason\Acme\Tests\Unit\Data;

use Jason\Acme\Data\Challenge;
use PHPUnit\Framework\TestCase;

class ChallengeTest extends TestCase
{
    public function testGetUrl(): void
    {
        $challenge = new Challenge(
            'https://acme.example.com/authz/123',
            'http-01',
            'pending',
            'https://acme.example.com/challenge/http/456',
            'abc123'
        );
        
        $this->assertEquals('https://acme.example.com/challenge/http/456', $challenge->getUrl());
    }

    public function testGetType(): void
    {
        $challenge = new Challenge(
            'https://acme.example.com/authz/123',
            'dns-01',
            'pending',
            'https://acme.example.com/challenge/dns/456',
            'abc123'
        );
        
        $this->assertEquals('dns-01', $challenge->getType());
    }

    public function testGetToken(): void
    {
        $challenge = new Challenge(
            'https://acme.example.com/authz/123',
            'http-01',
            'pending',
            'https://acme.example.com/challenge/http/456',
            'my-token-123'
        );
        
        $this->assertEquals('my-token-123', $challenge->getToken());
    }

    public function testGetStatus(): void
    {
        $challenge = new Challenge(
            'https://acme.example.com/authz/123',
            'http-01',
            'valid',
            'https://acme.example.com/challenge/http/456',
            'abc123'
        );
        
        $this->assertEquals('valid', $challenge->getStatus());
    }

    public function testGetAuthorizationURL(): void
    {
        $authUrl = 'https://acme.example.com/authz/123';
        $challenge = new Challenge(
            $authUrl,
            'http-01',
            'pending',
            'https://acme.example.com/challenge/http/456',
            'abc123'
        );
        
        $this->assertEquals($authUrl, $challenge->getAuthorizationURL());
    }
}
