<?php

declare(strict_types=1);

namespace Jason\Acme\Tests\Unit\Data;

use Jason\Acme\Data\Order;
use PHPUnit\Framework\TestCase;

class OrderTest extends TestCase
{
    public function testGetId(): void
    {
        $order = new Order(
            ['example.com'],
            'https://acme.example.com/acme/order/12345',
            'pending',
            '2024-01-01T12:00:00Z',
            [['type' => 'dns', 'value' => 'example.com']],
            ['https://acme.example.com/acme/authz/abc'],
            'https://acme.example.com/acme/finalize/12345'
        );
        
        $this->assertEquals('12345', $order->getId());
    }

    public function testGetURL(): void
    {
        $url = 'https://acme.example.com/acme/order/12345';
        $order = new Order(
            ['example.com'],
            $url,
            'pending',
            '2024-01-01T12:00:00Z',
            [['type' => 'dns', 'value' => 'example.com']],
            ['https://acme.example.com/acme/authz/abc'],
            'https://acme.example.com/acme/finalize/12345'
        );
        
        $this->assertEquals($url, $order->getURL());
    }

    public function testGetStatus(): void
    {
        $order = new Order(
            ['example.com'],
            'https://acme.example.com/acme/order/12345',
            'ready',
            '2024-01-01T12:00:00Z',
            [['type' => 'dns', 'value' => 'example.com']],
            ['https://acme.example.com/acme/authz/abc'],
            'https://acme.example.com/acme/finalize/12345'
        );
        
        $this->assertEquals('ready', $order->getStatus());
    }

    public function testGetDomains(): void
    {
        $domains = ['example.com', 'www.example.com'];
        $order = new Order(
            $domains,
            'https://acme.example.com/acme/order/12345',
            'pending',
            '2024-01-01T12:00:00Z',
            [
                ['type' => 'dns', 'value' => 'example.com'],
                ['type' => 'dns', 'value' => 'www.example.com']
            ],
            ['https://acme.example.com/acme/authz/abc'],
            'https://acme.example.com/acme/finalize/12345'
        );
        
        $this->assertEquals($domains, $order->getDomains());
    }

    public function testGetAuthorizationURLs(): void
    {
        $authUrls = [
            'https://acme.example.com/acme/authz/abc',
            'https://acme.example.com/acme/authz/def'
        ];
        $order = new Order(
            ['example.com', 'www.example.com'],
            'https://acme.example.com/acme/order/12345',
            'pending',
            '2024-01-01T12:00:00Z',
            [],
            $authUrls,
            'https://acme.example.com/acme/finalize/12345'
        );
        
        $this->assertEquals($authUrls, $order->getAuthorizationURLs());
    }

    public function testGetFinalizeURL(): void
    {
        $finalizeUrl = 'https://acme.example.com/acme/finalize/12345';
        $order = new Order(
            ['example.com'],
            'https://acme.example.com/acme/order/12345',
            'pending',
            '2024-01-01T12:00:00Z',
            [['type' => 'dns', 'value' => 'example.com']],
            ['https://acme.example.com/acme/authz/abc'],
            $finalizeUrl
        );
        
        $this->assertEquals($finalizeUrl, $order->getFinalizeURL());
    }

    public function testGetExpiresAt(): void
    {
        $order = new Order(
            ['example.com'],
            'https://acme.example.com/acme/order/12345',
            'pending',
            '2024-01-15T10:30:00Z',
            [['type' => 'dns', 'value' => 'example.com']],
            ['https://acme.example.com/acme/authz/abc'],
            'https://acme.example.com/acme/finalize/12345'
        );
        
        $expiresAt = $order->getExpiresAt();
        $this->assertInstanceOf(\DateTime::class, $expiresAt);
        $this->assertEquals('2024-01-15', $expiresAt->format('Y-m-d'));
    }

    public function testGetIdentifiers(): void
    {
        $identifiers = [
            ['type' => 'dns', 'value' => 'example.com'],
            ['type' => 'dns', 'value' => 'www.example.com']
        ];
        $order = new Order(
            ['example.com', 'www.example.com'],
            'https://acme.example.com/acme/order/12345',
            'pending',
            '2024-01-01T12:00:00Z',
            $identifiers,
            ['https://acme.example.com/acme/authz/abc'],
            'https://acme.example.com/acme/finalize/12345'
        );
        
        $this->assertEquals($identifiers, $order->getIdentifiers());
    }

    public function testExpiresAtWithMicroseconds(): void
    {
        $order = new Order(
            ['example.com'],
            'https://acme.example.com/acme/order/12345',
            'pending',
            '2024-01-01T12:00:00.123456Z',
            [['type' => 'dns', 'value' => 'example.com']],
            ['https://acme.example.com/acme/authz/abc'],
            'https://acme.example.com/acme/finalize/12345'
        );
        
        $expiresAt = $order->getExpiresAt();
        $this->assertEquals('2024-01-01', $expiresAt->format('Y-m-d'));
    }
}
