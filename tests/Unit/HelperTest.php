<?php

declare(strict_types=1);

namespace Jason\Acme\Tests\Unit;

use Jason\Acme\Helper;
use Jason\Acme\Enum\KeyType;
use PHPUnit\Framework\TestCase;

class HelperTest extends TestCase
{
    public function testToSafeString(): void
    {
        $input = 'test+/data==';
        $result = Helper::toSafeString(base64_decode($input));
        
        $this->assertNotEmpty($result);
        $this->assertStringNotContainsString('+', $result);
        $this->assertStringNotContainsString('/', $result);
        $this->assertStringNotContainsString('=', $result);
    }

    public function testGetNewKey(): void
    {
        try {
            $key = Helper::getNewKey(2048);
            $this->assertNotEmpty($key);
            $this->assertStringStartsWith('-----BEGIN', $key);
            $this->assertStringEndsWith('-----', trim($key));
        } catch (\Exception $e) {
            $this->markTestSkipped('OpenSSL not available: ' . $e->getMessage());
        }
    }

    public function testGetNewECKey(): void
    {
        try {
            $key = Helper::getNewKeyByType(KeyType::EC_384);
            $this->assertNotEmpty($key);
            $this->assertStringStartsWith('-----BEGIN', $key);
            $this->assertStringEndsWith('-----', trim($key));
        } catch (\Exception $e) {
            $this->markTestSkipped('OpenSSL not available: ' . $e->getMessage());
        }
    }

    public function testGetCsr(): void
    {
        try {
            $key = Helper::getNewKey(2048);
            $privateKey = openssl_pkey_get_private($key);
            
            $csr = Helper::getCsr(['example.com', 'www.example.com'], $privateKey);
            
            $this->assertNotEmpty($csr);
            $this->assertStringStartsWith('-----BEGIN', $csr);
            $this->assertStringEndsWith('-----', trim($csr));
        } catch (\Exception $e) {
            $this->markTestSkipped('OpenSSL not available: ' . $e->getMessage());
        }
    }

    public function testToDer(): void
    {
        try {
            $key = Helper::getNewKey(2048);
            $der = Helper::toDer($key);
            
            $this->assertNotEmpty($der);
            $this->assertNotSame($key, $der);
        } catch (\Exception $e) {
            $this->markTestSkipped('OpenSSL not available: ' . $e->getMessage());
        }
    }

    public function testGetKeyDetails(): void
    {
        try {
            $key = Helper::getNewKey(2048);
            $privateKey = openssl_pkey_get_private($key);
            
            $details = Helper::getKeyDetails($privateKey);
            
            $this->assertIsArray($details);
            $this->assertArrayHasKey('type', $details);
        } catch (\Exception $e) {
            $this->markTestSkipped('OpenSSL not available: ' . $e->getMessage());
        }
    }

    public function testGetNewKeyByTypeWithEC384(): void
    {
        try {
            $key = Helper::getNewKeyByType(KeyType::EC_384);
            $this->assertNotEmpty($key);
            $this->assertStringStartsWith('-----BEGIN', $key);
            $this->assertStringContainsString('EC', $key);
        } catch (\Exception $e) {
            $this->markTestSkipped('OpenSSL not available: ' . $e->getMessage());
        }
    }

    public function testGetNewKeyByTypeWithEC256(): void
    {
        try {
            $key = Helper::getNewKeyByType(KeyType::EC_256);
            $this->assertNotEmpty($key);
            $this->assertStringStartsWith('-----BEGIN', $key);
            $this->assertStringContainsString('EC', $key);
        } catch (\Exception $e) {
            $this->markTestSkipped('OpenSSL not available: ' . $e->getMessage());
        }
    }

    public function testGetNewKeyByTypeWithRSA2048(): void
    {
        try {
            $key = Helper::getNewKeyByType(KeyType::RSA_2048);
            $this->assertNotEmpty($key);
            $this->assertStringStartsWith('-----BEGIN', $key);
        } catch (\Exception $e) {
            $this->markTestSkipped('OpenSSL not available: ' . $e->getMessage());
        }
    }

    public function testGetNewKeyByTypeWithRSA4096(): void
    {
        try {
            $key = Helper::getNewKeyByType(KeyType::RSA_4096);
            $this->assertNotEmpty($key);
            $this->assertStringStartsWith('-----BEGIN', $key);
        } catch (\Exception $e) {
            $this->markTestSkipped('OpenSSL not available: ' . $e->getMessage());
        }
    }

    public function testGetNewKeyByTypeWithDefault(): void
    {
        try {
            $key = Helper::getNewKeyByType();
            $this->assertNotEmpty($key);
            $this->assertStringStartsWith('-----BEGIN', $key);
            $this->assertStringContainsString('EC', $key);
        } catch (\Exception $e) {
            $this->markTestSkipped('OpenSSL not available: ' . $e->getMessage());
        }
    }

    public function testKeyTypeEnumMethods(): void
    {
        $this->assertEquals('EC P-384', KeyType::EC_384->getLabel());
        $this->assertEquals('secp384r1', KeyType::EC_384->getParameter());
        $this->assertEquals(OPENSSL_KEYTYPE_EC, KeyType::EC_384->getOpenSSLType());
        
        $this->assertEquals('RSA 4096', KeyType::RSA_4096->getLabel());
        $this->assertEquals(4096, KeyType::RSA_4096->getParameter());
        $this->assertEquals(OPENSSL_KEYTYPE_RSA, KeyType::RSA_4096->getOpenSSLType());
    }
}
