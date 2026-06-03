<?php

namespace Jason\Acme;

use Jason\Acme\Enum\CertificateAuthority;
use Jason\Acme\Enum\ClientMode;
use Jason\Acme\Enum\KeyType;
use Jason\Acme\Exception\AcmeConfigurationException;
use League\Flysystem\Filesystem;

/**
 * Client 配置类
 * 
 * 用于约束和管理 ACME 客户端的初始化配置参数
 * 
 * @package Jason\Acme
 */
class ClientConfig
{
    /**
     * @var ClientMode 运行模式
     */
    protected ClientMode $mode = ClientMode::STAGING;

    /**
     * @var Filesystem 文件系统实例
     */
    protected Filesystem $filesystem;

    /**
     * @var string 文件系统中账户目录的前缀路径
     */
    protected string $basePath = 'le';

    /**
     * @var string|null LE 账户联系邮箱
     */
    protected ?string $username = null;

    /**
     * @var string|null 绑定 HTTP 请求的源 IP 地址
     */
    protected ?string $sourceIp = null;

    /**
     * @var KeyType 密钥类型
     */
    protected KeyType $keyType = KeyType::EC_384;

    /**
     * @var CertificateAuthority 证书颁发机构
     */
    protected CertificateAuthority $ca = CertificateAuthority::LETS_ENCRYPT;

    /**
     * @var array 额外配置项
     */
    protected array $extra = [];

    /**
     * ClientConfig 构造函数
     *
     * @param array $config 配置数组
     */
    public function __construct(array $config = [])
    {
        $this->loadFromArray($config);
    }

    /**
     * 从数组加载配置
     *
     * @param array $config
     *
     * @return self
     */
    public function loadFromArray(array $config): self
    {
        if (isset($config['mode'])) {
            $this->setMode($config['mode']);
        }

        if (isset($config['fs'])) {
            $this->setFilesystem($config['fs']);
        }

        if (isset($config['basePath'])) {
            $this->setBasePath($config['basePath']);
        }

        if (isset($config['username'])) {
            $this->setUsername($config['username']);
        }

        if (isset($config['source_ip'])) {
            $this->setSourceIp($config['source_ip']);
        }

        if (isset($config['key_type'])) {
            $this->setKeyType($config['key_type']);
        }

        if (isset($config['ca'])) {
            $this->setCa($config['ca']);
        }

        // 保留额外配置项
        $knownKeys = ['mode', 'fs', 'basePath', 'username', 'source_ip', 'key_type', 'ca'];
        foreach ($config as $key => $value) {
            if (!in_array($key, $knownKeys, true)) {
                $this->extra[$key] = $value;
            }
        }

        $this->validate();

        return $this;
    }

    /**
     * 校验配置参数
     *
     * @throws \InvalidArgumentException 当配置无效时抛出
     */
    public function validate(): void
    {
        // 校验模式（现在是枚举类型，不需要额外校验）
        if (!$this->mode instanceof ClientMode) {
            throw new AcmeConfigurationException(sprintf('Invalid mode type: %s', gettype($this->mode)));
        }

        // 校验文件系统
        if (!isset($this->filesystem)) {
            throw new AcmeConfigurationException('Filesystem is required');
        }

        // 校验邮箱格式
        if ($this->username !== null && !filter_var($this->username, FILTER_VALIDATE_EMAIL)) {
            throw new AcmeConfigurationException(sprintf('Invalid email address: %s', $this->username));
        }

        // 校验 IP 地址格式
        if ($this->sourceIp !== null && !filter_var($this->sourceIp, FILTER_VALIDATE_IP)) {
            throw new AcmeConfigurationException(sprintf('Invalid IP address: %s', $this->sourceIp));
        }

        // 校验基础路径
        if (empty($this->basePath) || !preg_match('/^[\w\/\-]+$/', $this->basePath)) {
            throw new AcmeConfigurationException(sprintf('Invalid basePath: %s', $this->basePath));
        }
    }

    /**
     * 获取模式
     *
     * @return ClientMode
     */
    public function getMode(): ClientMode
    {
        return $this->mode;
    }

    /**
     * 设置模式
     *
     * @param ClientMode|string $mode  枚举值或字符串（'live'/'staging'）
     *
     * @return self
     * @throws \InvalidArgumentException
     */
    public function setMode(ClientMode|string $mode): self
    {
        if (is_string($mode)) {
            $mode = ClientMode::tryFrom($mode)
                ?? throw new AcmeConfigurationException(
                    sprintf('Invalid mode "%s". Allowed values: live, staging', $mode)
                );
        }

        $this->mode = $mode;

        return $this;
    }

    /**
     * 获取文件系统
     *
     * @return Filesystem
     */
    public function getFilesystem(): Filesystem
    {
        return $this->filesystem;
    }

    /**
     * 设置文件系统
     *
     * @param Filesystem $filesystem
     *
     * @return self
     */
    public function setFilesystem(Filesystem $filesystem): self
    {
        $this->filesystem = $filesystem;

        return $this;
    }

    /**
     * 获取基础路径
     *
     * @return string
     */
    public function getBasePath(): string
    {
        return $this->basePath;
    }

    /**
     * 设置基础路径
     *
     * @param string $basePath
     *
     * @return self
     * @throws \InvalidArgumentException
     */
    public function setBasePath(string $basePath): self
    {
        $basePath = trim($basePath);
        if (empty($basePath) || !preg_match('/^[\w\/\-]+$/', $basePath)) {
            throw new AcmeConfigurationException(sprintf('Invalid basePath: %s', $basePath));
        }

        $this->basePath = $basePath;

        return $this;
    }

    /**
     * 获取用户名（邮箱）
     *
     * @return string|null
     */
    public function getUsername(): ?string
    {
        return $this->username;
    }

    /**
     * 设置用户名（邮箱）
     *
     * @param string|null $username
     *
     * @return self
     * @throws \InvalidArgumentException
     */
    public function setUsername(?string $username): self
    {
        if ($username !== null && !filter_var($username, FILTER_VALIDATE_EMAIL)) {
            throw new AcmeConfigurationException(sprintf('Invalid email address: %s', $username));
        }

        $this->username = $username;

        return $this;
    }

    /**
     * 获取源 IP 地址
     *
     * @return string|null
     */
    public function getSourceIp(): ?string
    {
        return $this->sourceIp;
    }

    /**
     * 设置源 IP 地址
     *
     * @param string|null $sourceIp
     *
     * @return self
     * @throws \InvalidArgumentException
     */
    public function setSourceIp(?string $sourceIp): self
    {
        if ($sourceIp !== null && !filter_var($sourceIp, FILTER_VALIDATE_IP)) {
            throw new AcmeConfigurationException(sprintf('Invalid IP address: %s', $sourceIp));
        }

        $this->sourceIp = $sourceIp;

        return $this;
    }

    /**
     * 获取密钥类型
     *
     * @return KeyType
     */
    public function getKeyType(): KeyType
    {
        return $this->keyType;
    }

    /**
     * 设置密钥类型
     *
     * @param KeyType|string $keyType  枚举值或字符串
     *
     * @return self
     * @throws \InvalidArgumentException
     */
    public function setKeyType(KeyType|string $keyType): self
    {
        if (is_string($keyType)) {
            $keyType = match ($keyType) {
                'ec_256' => KeyType::EC_256,
                'ec_384' => KeyType::EC_384,
                'rsa_2048' => KeyType::RSA_2048,
                'rsa_3072' => KeyType::RSA_3072,
                'rsa_4096' => KeyType::RSA_4096,
                'ec' => KeyType::EC_384,
                'rsa' => KeyType::RSA_4096,
                default => throw new AcmeConfigurationException(
                    sprintf('Invalid key_type "%s". Allowed values: ec_256, ec_384, rsa_2048, rsa_3072, rsa_4096, ec, rsa', $keyType)
                ),
            };
        }

        $this->keyType = $keyType;

        return $this;
    }

    /**
     * 获取证书颁发机构
     *
     * @return CertificateAuthority
     */
    public function getCa(): CertificateAuthority
    {
        return $this->ca;
    }

    /**
     * 设置证书颁发机构
     *
     * @param CertificateAuthority|string $ca  枚举值或字符串（'lets_encrypt'/'zero_ssl'）
     *
     * @return self
     * @throws \InvalidArgumentException
     */
    public function setCa(CertificateAuthority|string $ca): self
    {
        if (is_string($ca)) {
            $ca = CertificateAuthority::tryFrom($ca)
                ?? throw new AcmeConfigurationException(
                    sprintf('Invalid CA "%s". Allowed values: lets_encrypt, zero_ssl', $ca)
                );
        }

        $this->ca = $ca;

        return $this;
    }

    /**
     * 获取额外配置项
     *
     * @param string|null $key 配置键名，不传则返回所有额外配置
     * @param mixed|null $default 默认值
     *
     * @return mixed
     */
    public function getExtra(?string $key = null, mixed $default = null): mixed
    {
        if ($key === null) {
            return $this->extra;
        }

        return $this->extra[$key] ?? $default;
    }

    /**
     * 设置额外配置项
     *
     * @param string $key
     * @param mixed $value
     *
     * @return self
     */
    public function setExtra(string $key, mixed $value): self
    {
        $this->extra[$key] = $value;

        return $this;
    }

    /**
     * 转换为数组
     *
     * @return array
     */
    public function toArray(): array
    {
        return [
            'mode' => $this->mode->value,
            'fs' => $this->filesystem,
            'basePath' => $this->basePath,
            'username' => $this->username,
            'source_ip' => $this->sourceIp,
            'key_type' => $this->keyType->value,
            'ca' => $this->ca->value,
            ...$this->extra,
        ];
    }

    /**
     * 创建配置实例（静态工厂方法）
     *
     * @param array $config
     *
     * @return self
     */
    public static function create(array $config = []): self
    {
        return new self($config);
    }

    /**
     * 创建生产环境配置
     *
     * @param Filesystem $filesystem
     * @param string|null $username
     *
     * @return self
     */
    public static function createLive(Filesystem $filesystem, ?string $username = null): self
    {
        return new self([
            'mode' => ClientMode::LIVE,
            'fs' => $filesystem,
            'username' => $username,
        ]);
    }

    /**
     * 创建测试环境配置
     *
     * @param Filesystem $filesystem
     * @param string|null $username
     *
     * @return self
     */
    public static function createStaging(Filesystem $filesystem, ?string $username = null): self
    {
        return new self([
            'mode' => ClientMode::STAGING,
            'fs' => $filesystem,
            'username' => $username,
        ]);
    }

    /**
     * 创建 ZeroSSL 配置
     *
     * @param Filesystem $filesystem
     * @param string|null $username
     *
     * @return self
     */
    public static function createZeroSSL(Filesystem $filesystem, ?string $username = null): self
    {
        return new self([
            'mode' => ClientMode::LIVE,
            'ca' => CertificateAuthority::ZERO_SSL,
            'fs' => $filesystem,
            'username' => $username,
        ]);
    }
}
