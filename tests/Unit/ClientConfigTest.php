<?php

declare(strict_types=1);

namespace Jason\Acme\Tests\Unit;

use Jason\Acme\ClientConfig;
use Jason\Acme\Enum\ClientMode;
use Jason\Acme\Enum\KeyType;
use League\Flysystem\Filesystem;
use Mockery;
use PHPUnit\Framework\TestCase;

class ClientConfigTest extends TestCase
{
    protected function tearDown(): void
    {
        Mockery::close();
    }

    public function testCreateWithArray(): void
    {
        $filesystem = Mockery::mock(Filesystem::class);
        
        $config = ClientConfig::create([
            'mode' => ClientMode::LIVE,
            'fs' => $filesystem,
            'username' => 'test@example.com',
            'key_type' => KeyType::RSA_2048,
        ]);
        
        $this->assertInstanceOf(ClientConfig::class, $config);
        $this->assertEquals(ClientMode::LIVE, $config->getMode());
        $this->assertSame($filesystem, $config->getFilesystem());
        $this->assertEquals('test@example.com', $config->getUsername());
        $this->assertEquals(KeyType::RSA_2048, $config->getKeyType());
    }

    public function testCreateLive(): void
    {
        $filesystem = Mockery::mock(Filesystem::class);
        
        $config = ClientConfig::createLive($filesystem, 'test@example.com');
        
        $this->assertEquals(ClientMode::LIVE, $config->getMode());
        $this->assertSame($filesystem, $config->getFilesystem());
        $this->assertEquals('test@example.com', $config->getUsername());
    }

    public function testCreateStaging(): void
    {
        $filesystem = Mockery::mock(Filesystem::class);
        
        $config = ClientConfig::createStaging($filesystem);
        
        $this->assertEquals(ClientMode::STAGING, $config->getMode());
        $this->assertSame($filesystem, $config->getFilesystem());
        $this->assertNull($config->getUsername());
    }

    public function testDefaultValues(): void
    {
        $filesystem = Mockery::mock(Filesystem::class);
        
        $config = ClientConfig::create(['fs' => $filesystem]);
        
        $this->assertEquals(ClientMode::STAGING, $config->getMode());
        $this->assertEquals('le', $config->getBasePath());
        $this->assertEquals(KeyType::EC_384, $config->getKeyType());
        $this->assertNull($config->getUsername());
        $this->assertNull($config->getSourceIp());
    }

    public function testSettersAndGetters(): void
    {
        $filesystem = Mockery::mock(Filesystem::class);
        
        $config = new ClientConfig(['fs' => $filesystem]);
        
        $config->setMode(ClientMode::LIVE)
               ->setUsername('user@example.com')
               ->setSourceIp('192.168.1.1')
               ->setBasePath('custom-path')
               ->setKeyType(KeyType::RSA_4096);
        
        $this->assertEquals(ClientMode::LIVE, $config->getMode());
        $this->assertEquals('user@example.com', $config->getUsername());
        $this->assertEquals('192.168.1.1', $config->getSourceIp());
        $this->assertEquals('custom-path', $config->getBasePath());
        $this->assertEquals(KeyType::RSA_4096, $config->getKeyType());
    }

    public function testInvalidEmailThrowsException(): void
    {
        $filesystem = Mockery::mock(Filesystem::class);
        
        $this->expectException(\InvalidArgumentException::class);
        
        ClientConfig::create([
            'fs' => $filesystem,
            'username' => 'invalid-email',
        ]);
    }

    public function testInvalidIpThrowsException(): void
    {
        $filesystem = Mockery::mock(Filesystem::class);
        
        $this->expectException(\InvalidArgumentException::class);
        
        ClientConfig::create([
            'fs' => $filesystem,
            'source_ip' => 'invalid-ip',
        ]);
    }

    public function testMissingFilesystemThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Filesystem is required');
        
        ClientConfig::create(['username' => 'test@example.com']);
    }

    public function testExtraConfig(): void
    {
        $filesystem = Mockery::mock(Filesystem::class);
        
        $config = ClientConfig::create([
            'fs' => $filesystem,
            'custom_option' => 'custom_value',
            'another_option' => 123,
        ]);
        
        $this->assertEquals('custom_value', $config->getExtra('custom_option'));
        $this->assertEquals(123, $config->getExtra('another_option'));
        $this->assertNull($config->getExtra('non_existent'));
        $this->assertEquals('default', $config->getExtra('non_existent', 'default'));
        
        $config->setExtra('new_option', 'new_value');
        $this->assertEquals('new_value', $config->getExtra('new_option'));
    }

    public function testToArray(): void
    {
        $filesystem = Mockery::mock(Filesystem::class);
        
        $config = ClientConfig::create([
            'mode' => ClientMode::LIVE,
            'fs' => $filesystem,
            'username' => 'test@example.com',
            'custom' => 'value',
        ]);
        
        $array = $config->toArray();
        
        $this->assertEquals('live', $array['mode']);
        $this->assertSame($filesystem, $array['fs']);
        $this->assertEquals('test@example.com', $array['username']);
        $this->assertEquals('value', $array['custom']);
        $this->assertEquals('ec_384', $array['key_type']);
    }
}
