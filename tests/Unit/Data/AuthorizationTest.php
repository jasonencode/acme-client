<?php

declare(strict_types=1);

namespace Jason\Acme\Tests\Unit\Data;

use Jason\Acme\Client;
use Jason\Acme\Data\Authorization;
use Jason\Acme\Data\Challenge;
use PHPUnit\Framework\TestCase;

class AuthorizationTest extends TestCase
{
    public function testGetDomain(): void
    {
        $authorization = new Authorization('example.com', '2024-01-01T12:00:00Z', 'test-digest');
        
        $this->assertEquals('example.com', $authorization->getDomain());
    }

    public function testGetExpires(): void
    {
        $authorization = new Authorization('example.com', '2024-06-15T10:30:00Z', 'test-digest');
        
        $expires = $authorization->getExpires();
        $this->assertInstanceOf(\DateTime::class, $expires);
        $this->assertEquals('2024-06-15', $expires->format('Y-m-d'));
    }

    public function testGetChallenges(): void
    {
        $authorization = new Authorization('example.com', '2024-01-01T12:00:00Z', 'test-digest');
        
        $this->assertEquals([], $authorization->getChallenges());
        
        $challenge1 = new Challenge(
            'https://acme.example.com/authz/123',
            'http-01',
            'pending',
            'https://acme.example.com/challenge/http/456',
            'token1'
        );
        $authorization->addChallenge($challenge1);
        
        $this->assertCount(1, $authorization->getChallenges());
        $this->assertEquals($challenge1, $authorization->getChallenges()[0]);
    }

    public function testGetHttpChallenge(): void
    {
        $authorization = new Authorization('example.com', '2024-01-01T12:00:00Z', 'test-digest');
        
        $httpChallenge = new Challenge(
            'https://acme.example.com/authz/123',
            'http-01',
            'pending',
            'https://acme.example.com/challenge/http/456',
            'http-token'
        );
        $dnsChallenge = new Challenge(
            'https://acme.example.com/authz/123',
            'dns-01',
            'pending',
            'https://acme.example.com/challenge/dns/789',
            'dns-token'
        );
        
        $authorization->addChallenge($dnsChallenge);
        $authorization->addChallenge($httpChallenge);
        
        $result = $authorization->getHttpChallenge();
        $this->assertInstanceOf(Challenge::class, $result);
        $this->assertEquals('http-01', $result->getType());
        $this->assertEquals('http-token', $result->getToken());
    }

    public function testGetHttpChallengeReturnsFalseWhenNotPresent(): void
    {
        $authorization = new Authorization('example.com', '2024-01-01T12:00:00Z', 'test-digest');
        
        $dnsChallenge = new Challenge(
            'https://acme.example.com/authz/123',
            'dns-01',
            'pending',
            'https://acme.example.com/challenge/dns/789',
            'dns-token'
        );
        $authorization->addChallenge($dnsChallenge);
        
        $this->assertFalse($authorization->getHttpChallenge());
    }

    public function testGetDnsChallenge(): void
    {
        $authorization = new Authorization('example.com', '2024-01-01T12:00:00Z', 'test-digest');
        
        $httpChallenge = new Challenge(
            'https://acme.example.com/authz/123',
            'http-01',
            'pending',
            'https://acme.example.com/challenge/http/456',
            'http-token'
        );
        $dnsChallenge = new Challenge(
            'https://acme.example.com/authz/123',
            'dns-01',
            'pending',
            'https://acme.example.com/challenge/dns/789',
            'dns-token'
        );
        
        $authorization->addChallenge($httpChallenge);
        $authorization->addChallenge($dnsChallenge);
        
        $result = $authorization->getDnsChallenge();
        $this->assertInstanceOf(Challenge::class, $result);
        $this->assertEquals('dns-01', $result->getType());
        $this->assertEquals('dns-token', $result->getToken());
    }

    public function testGetDnsChallengeReturnsFalseWhenNotPresent(): void
    {
        $authorization = new Authorization('example.com', '2024-01-01T12:00:00Z', 'test-digest');
        
        $httpChallenge = new Challenge(
            'https://acme.example.com/authz/123',
            'http-01',
            'pending',
            'https://acme.example.com/challenge/http/456',
            'http-token'
        );
        $authorization->addChallenge($httpChallenge);
        
        $this->assertFalse($authorization->getDnsChallenge());
    }

    public function testGetFile(): void
    {
        $digest = 'test-digest-value';
        $authorization = new Authorization('example.com', '2024-01-01T12:00:00Z', $digest);
        
        $httpChallenge = new Challenge(
            'https://acme.example.com/authz/123',
            'http-01',
            'pending',
            'https://acme.example.com/challenge/http/456',
            'http-token'
        );
        $authorization->addChallenge($httpChallenge);
        
        $file = $authorization->getFile();
        $this->assertInstanceOf(\Jason\Acme\Data\File::class, $file);
        $this->assertEquals('http-token', $file->getFilename());
        $this->assertEquals('http-token.' . $digest, $file->getContents());
    }

    public function testGetFileReturnsFalseWhenNoHttpChallenge(): void
    {
        $authorization = new Authorization('example.com', '2024-01-01T12:00:00Z', 'test-digest');
        
        $dnsChallenge = new Challenge(
            'https://acme.example.com/authz/123',
            'dns-01',
            'pending',
            'https://acme.example.com/challenge/dns/789',
            'dns-token'
        );
        $authorization->addChallenge($dnsChallenge);
        
        $this->assertFalse($authorization->getFile());
    }

    public function testGetTxtRecord(): void
    {
        $digest = 'test-digest-value';
        $authorization = new Authorization('example.com', '2024-01-01T12:00:00Z', $digest);
        
        $dnsChallenge = new Challenge(
            'https://acme.example.com/authz/123',
            'dns-01',
            'pending',
            'https://acme.example.com/challenge/dns/789',
            'dns-token'
        );
        $authorization->addChallenge($dnsChallenge);
        
        $record = $authorization->getTxtRecord();
        $this->assertInstanceOf(\Jason\Acme\Data\Record::class, $record);
        $this->assertEquals('_acme-challenge.example.com', $record->getName());
        $this->assertNotEmpty($record->getValue());
    }

    public function testGetTxtRecordReturnsFalseWhenNoDnsChallenge(): void
    {
        $authorization = new Authorization('example.com', '2024-01-01T12:00:00Z', 'test-digest');
        
        $httpChallenge = new Challenge(
            'https://acme.example.com/authz/123',
            'http-01',
            'pending',
            'https://acme.example.com/challenge/http/456',
            'http-token'
        );
        $authorization->addChallenge($httpChallenge);
        
        $this->assertFalse($authorization->getTxtRecord());
    }
}
