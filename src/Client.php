<?php

namespace Jason\Acme;

use Jason\Acme\Data\Account;
use Jason\Acme\Data\Authorization;
use Jason\Acme\Data\Certificate;
use Jason\Acme\Data\Challenge;
use Jason\Acme\Data\Order;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\RequestException;
use League\Flysystem\Filesystem;
use Psr\Http\Message\ResponseInterface;

class Client
{
    /**
     * 生产环境 URL
     */
    const DIRECTORY_LIVE = 'https://acme-v02.api.letsencrypt.org/directory';

    /**
     * 测试环境 URL
     */
    const DIRECTORY_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';

    /**
     * 生产环境标识
     */
    const MODE_LIVE = 'live';

    /**
     * 测试环境标识
     */
    const MODE_STAGING = 'staging';

    /**
     * 新账户目录
     */
    const DIRECTORY_NEW_ACCOUNT = 'newAccount';

    /**
     * Nonce 目录
     */
    const DIRECTORY_NEW_NONCE = 'newNonce';

    /**
     * 证书订单目录
     */
    const DIRECTORY_NEW_ORDER = 'newOrder';

    /**
     * HTTP 验证方式
     */
    const VALIDATION_HTTP = 'http-01';

    /**
     * DNS 验证方式
     */
    const VALIDATION_DNS = 'dns-01';

    /**
     * @var string
     */
    protected $nonce;

    /**
     * @var Account
     */
    protected $account;

    /**
     * @var array
     */
    protected $privateKeyDetails;

    /**
     * @var string
     */
    protected $accountKey;

    /**
     * @var Filesystem
     */
    protected $filesystem;

    /**
     * @var array
     */
    protected $directories = [];

    /**
     * @var array
     */
    protected $header = [];

    /**
     * @var string
     */
    protected $digest;

    /**
     * @var HttpClient
     */
    protected $httpClient;

    /**
     * @var array
     */
    protected $config;

    /**
     * Client 构造函数
     *
     * @param array $config
     *
     * @type string $mode ACME 模式（production / staging）
     * @type Filesystem $fs 用于存储静态数据的文件系统
     * @type string $basePath 文件系统的基础路径（用于存储账户信息和 CSR / 密钥）
     * @type string $username ACME 用户名
     * @type string $source_ip Guzzle 的源 IP（通过 curl.options 绑定，默认为 0.0.0.0 [操作系统默认值]）
     * }
     */
    public function __construct($config = [])
    {
        $this->config = $config;
        if ($this->getOption('fs', false)) {
            $this->filesystem = $this->getOption('fs');
        } else {
            throw new \LogicException('No filesystem option supplied');
        }

        if ($this->getOption('username', false) === false) {
            throw new \LogicException('Username not provided');
        }

        $this->init();
    }

    /**
     * 根据 ID 获取现有订单
     *
     * @param $id
     * @return Order
     * @throws \Exception
     */
    public function getOrder($id): Order
    {
        $url = str_replace('new-order', 'order', $this->getUrl(self::DIRECTORY_NEW_ORDER));
        $url = $url . '/' . $this->getAccount()->getId() . '/' . $id;
        $response = $this->request($url, $this->signPayloadKid(null, $url));
        $data = json_decode((string)$response->getBody(), true);

        $domains = [];
        foreach ($data['identifiers'] as $identifier) {
            $domains[] = $identifier['value'];
        }

        return new Order(
            $domains,
            $url,
            $data['status'],
            $data['expires'],
            $data['identifiers'],
            $data['authorizations'],
            $data['finalize']
        );
    }

    /**
     * 获取订单就绪状态
     *
     * @param Order $order
     * @return bool
     * @throws \Exception
     */
    public function isReady(Order $order): bool
    {
        $order = $this->getOrder($order->getId());
        return $order->getStatus() == 'ready';
    }


    /**
     * 创建新订单
     *
     * @param array $domains
     * @return Order
     * @throws \Exception
     */
    public function createOrder(array $domains): Order
    {
        $identifiers = [];
        foreach ($domains as $domain) {
            $identifiers[] =
                [
                    'type'  => 'dns',
                    'value' => $domain,
                ];
        }

        $url = $this->getUrl(self::DIRECTORY_NEW_ORDER);
        $response = $this->request($url, $this->signPayloadKid(
            [
                'identifiers' => $identifiers,
            ],
            $url
        ));

        $data = json_decode((string)$response->getBody(), true);
        $order = new Order(
            $domains,
            $response->getHeaderLine('location'),
            $data['status'],
            $data['expires'],
            $data['identifiers'],
            $data['authorizations'],
            $data['finalize']
        );


        return $order;
    }

    /**
     * 获取授权
     *
     * @param Order $order
     * @return array|Authorization[]
     * @throws \Exception
     */
    public function authorize(Order $order): array
    {
        $authorizations = [];
        foreach ($order->getAuthorizationURLs() as $authorizationURL) {
            $response = $this->request(
                $authorizationURL,
                $this->signPayloadKid(null, $authorizationURL)
            );
            $data = json_decode((string)$response->getBody(), true);
            $authorization = new Authorization($data['identifier']['value'], $data['expires'], $this->getDigest());

            foreach ($data['challenges'] as $challengeData) {
                $challenge = new Challenge(
                    $authorizationURL,
                    $challengeData['type'],
                    $challengeData['status'],
                    $challengeData['url'],
                    $challengeData['token']
                );
                $authorization->addChallenge($challenge);
            }
            $authorizations[] = $authorization;
        }

        return $authorizations;
    }

    /**
     * 运行授权自测
     * @param Authorization $authorization
     * @param string $type
     * @param int $maxAttempts
     * @return bool
     */
    public function selfTest(Authorization $authorization, $type = self::VALIDATION_HTTP, $maxAttempts = 15): bool
    {
        if ($type == self::VALIDATION_HTTP) {
            return $this->selfHttpTest($authorization, $maxAttempts);
        } elseif ($type == self::VALIDATION_DNS) {
            return $this->selfDNSTest($authorization, $maxAttempts);
        }
        return false;
    }

    /**
     * 验证挑战
     *
     * @param Challenge $challenge
     * @param int $maxAttempts
     * @return bool
     * @throws \Exception
     */
    public function validate(Challenge $challenge, int $maxAttempts = 15): bool
    {
        $this->request(
            $challenge->getUrl(),
            $this->signPayloadKid([
                'keyAuthorization' => $challenge->getToken() . '.' . $this->getDigest()
            ], $challenge->getUrl())
        );

        $data = [];
        do {
            $response = $this->request(
                $challenge->getAuthorizationURL(),
                $this->signPayloadKid(null, $challenge->getAuthorizationURL())
            );
            $data = json_decode((string)$response->getBody(), true);
            if ($maxAttempts > 1 && $data['status'] != 'valid') {
                sleep(ceil(15 / $maxAttempts));
            }
            $maxAttempts--;
        } while ($maxAttempts > 0 && $data['status'] != 'valid');

        return (isset($data['status']) && $data['status'] == 'valid');
    }

    /**
     * 返回证书
     *
     * @param Order $order
     * @return Certificate
     * @throws \Exception
     */
    public function getCertificate(Order $order): Certificate
    {
        $privateKey = Helper::getNewECKey();
        $csr = Helper::getCsr($order->getDomains(), $privateKey);
        $der = Helper::toDer($csr);

        $response = $this->request(
            $order->getFinalizeURL(),
            $this->signPayloadKid(
                ['csr' => Helper::toSafeString($der)],
                $order->getFinalizeURL()
            )
        );

        $data = json_decode((string)$response->getBody(), true);
        $certificateResponse = $this->request(
            $data['certificate'],
            $this->signPayloadKid(null, $data['certificate'])
        );
        $chain = $str = preg_replace('/^[ \t]*[\r\n]+/m', '', (string)$certificateResponse->getBody());
        return new Certificate($privateKey, $csr, $chain);
    }


    /**
     * 返回 Let's Encrypt 账户信息
     *
     * @return Account
     * @throws \Exception
     */
    public function getAccount(): Account
    {
        $response = $this->request(
            $this->getUrl(self::DIRECTORY_NEW_ACCOUNT),
            $this->signPayloadJWK(
                [
                    'onlyReturnExisting' => true,
                ],
                $this->getUrl(self::DIRECTORY_NEW_ACCOUNT)
            )
        );

        $data = json_decode((string)$response->getBody(), true);
        $accountURL = $response->getHeaderLine('Location');
        $date = (new \DateTime())->setTimestamp(strtotime($data['createdAt']));
        return new Account($date, ($data['status'] == 'valid'), $accountURL);
    }

    /**
     * 返回配置了 ACME API 的 Guzzle 客户端
     * @return HttpClient
     */
    protected function getHttpClient()
    {
        if ($this->httpClient === null) {
            $config = [
                'base_uri' => (
                ($this->getOption('mode', self::MODE_LIVE) == self::MODE_LIVE) ?
                    self::DIRECTORY_LIVE : self::DIRECTORY_STAGING),
            ];
            if ($this->getOption('source_ip', false) !== false) {
                $config['curl.options']['CURLOPT_INTERFACE'] = $this->getOption('source_ip');
            }
            $this->httpClient = new HttpClient($config);
        }
        return $this->httpClient;
    }

    /**
     * 返回用于自测的 Guzzle 客户端
     * @return HttpClient
     */
    protected function getSelfTestClient()
    {
        return new HttpClient([
            'verify'          => false,
            'timeout'         => 10,
            'connect_timeout' => 3,
            'allow_redirects' => true,
        ]);
    }

    /**
     * HTTP 自测
     * @param Authorization $authorization
     * @param $maxAttempts
     * @return bool
     */
    protected function selfHttpTest(Authorization $authorization, $maxAttempts)
    {
        do {
            $maxAttempts--;
            try {
                $response = $this->getSelfTestClient()->request(
                    'GET',
                    'http://' . $authorization->getDomain() . '/.well-known/acme-challenge/' .
                    $authorization->getFile()->getFilename()
                );
                $contents = (string)$response->getBody();
                if ($contents == $authorization->getFile()->getContents()) {
                    return true;
                }
            } catch (RequestException $e) {
            }
        } while ($maxAttempts > 0);

        return false;
    }

    /**
     * 使用 Cloudflare DNS API 的 DNS 自测
     * @param Authorization $authorization
     * @param $maxAttempts
     * @return bool
     */
    protected function selfDNSTest(Authorization $authorization, $maxAttempts)
    {
        do {
            $response = $this->getSelfTestDNSClient()->get(
                '/dns-query',
                [
                    'query' => [
                        'name' => $authorization->getTxtRecord()->getName(),
                        'type' => 'TXT'
                    ]
                ]
            );
            $data = json_decode((string)$response->getBody(), true);
            if (isset($data['Answer'])) {
                foreach ($data['Answer'] as $result) {
                    if (trim($result['data'], "\"") == $authorization->getTxtRecord()->getValue()) {
                        return true;
                    }
                }
            }
            if ($maxAttempts > 1) {
                sleep(ceil(45 / $maxAttempts));
            }
            $maxAttempts--;
        } while ($maxAttempts > 0);

        return false;
    }

    /**
     * 返回预配置的 Cloudflare DNS API 客户端
     * @return HttpClient
     */
    protected function getSelfTestDNSClient()
    {
        return new HttpClient([
            'base_uri'        => 'https://cloudflare-dns.com',
            'connect_timeout' => 10,
            'headers'         => [
                'Accept' => 'application/dns-json',
            ],
        ]);
    }

    /**
     * 初始化客户端
     */
    protected function init()
    {
        //从 LE API 加载目录
        $response = $this->getHttpClient()->get('/directory');
        $result = \GuzzleHttp\json_decode((string)$response->getBody(), true);
        $this->directories = $result;

        //准备 LE 账户
        $this->loadKeys();
        $this->tosAgree();
        $this->account = $this->getAccount();
    }

    protected function loadKeys()
    {
        //确保私钥已就位
        if ($this->getFilesystem()->has($this->getPath('account.pem')) === false) {
            $this->getFilesystem()->write(
                $this->getPath('account.pem'),
                Helper::getNewKey($this->getOption('key_length', 4096))
            );
        }
        $privateKey = $this->getFilesystem()->read($this->getPath('account.pem'));
        $privateKey = openssl_pkey_get_private($privateKey);
        $this->privateKeyDetails = openssl_pkey_get_details($privateKey);
    }

    /**
     * 同意服务条款
     *
     * @throws \Exception
     */
    protected function tosAgree()
    {
        $this->request(
            $this->getUrl(self::DIRECTORY_NEW_ACCOUNT),
            $this->signPayloadJWK(
                [
                    'contact'              => [
                        'mailto:' . $this->getOption('username'),
                    ],
                    'termsOfServiceAgreed' => true,
                ],
                $this->getUrl(self::DIRECTORY_NEW_ACCOUNT)
            )
        );
    }

    /**
     * 获取格式化的路径
     *
     * @param null $path
     * @return string
     */
    protected function getPath($path = null): string
    {
        $userDirectory = preg_replace('/[^a-z0-9]+/', '-', strtolower($this->getOption('username')));

        return $this->getOption(
            'basePath',
            'le'
        ) . DIRECTORY_SEPARATOR . $userDirectory . ($path === null ? '' : DIRECTORY_SEPARATOR . $path);
    }

    /**
     * 返回 Flysystem 文件系统
     * @return Filesystem
     */
    protected function getFilesystem(): Filesystem
    {
        return $this->filesystem;
    }

    /**
     * 获取配置选项
     *
     * @param      $key
     * @param null $default
     *
     * @return mixed|null
     */
    protected function getOption($key, $default = null)
    {
        if (isset($this->config[$key])) {
            return $this->config[$key];
        }

        return $default;
    }

    /**
     * 获取密钥指纹
     *
     * @return string
     * @throws \Exception
     */
    protected function getDigest(): string
    {
        if ($this->digest === null) {
            $this->digest = Helper::toSafeString(hash('sha256', json_encode($this->getJWKHeader()), true));
        }

        return $this->digest;
    }

    /**
     * 向 LE API 发送请求
     *
     * @param $url
     * @param array $payload
     * @param string $method
     * @return ResponseInterface
     */
    protected function request($url, $payload = [], $method = 'POST'): ResponseInterface
    {
        try {
            $response = $this->getHttpClient()->request($method, $url, [
                'json'    => $payload,
                'headers' => [
                    'Content-Type' => 'application/jose+json',
                ]
            ]);
            $this->nonce = $response->getHeaderLine('replay-nonce');
        } catch (ClientException $e) {
            throw $e;
        }

        return $response;
    }

    /**
     * 获取 LE 目录路径
     *
     * @param $directory
     *
     * @return mixed
     * @throws \Exception
     */
    protected function getUrl($directory): string
    {
        if (isset($this->directories[$directory])) {
            return $this->directories[$directory];
        }

        throw new \Exception('Invalid directory: ' . $directory . ' not listed');
    }


    /**
     * 获取密钥
     *
     * @return bool|resource|string
     * @throws \Exception
     */
    protected function getAccountKey()
    {
        if ($this->accountKey === null) {
            $this->accountKey = openssl_pkey_get_private($this->getFilesystem()
                ->read($this->getPath('account.pem')));
        }

        if ($this->accountKey === false) {
            throw new \Exception('Invalid account key');
        }

        return $this->accountKey;
    }

    /**
     * 获取请求头
     *
     * @return array
     * @throws \Exception
     */
    protected function getJWKHeader(): array
    {
        return [
            'e'   => Helper::toSafeString(Helper::getKeyDetails($this->getAccountKey())['rsa']['e']),
            'kty' => 'RSA',
            'n'   => Helper::toSafeString(Helper::getKeyDetails($this->getAccountKey())['rsa']['n']),
        ];
    }

    /**
     * 获取 JWK 信封
     *
     * @param $url
     * @return array
     * @throws \Exception
     */
    protected function getJWK($url): array
    {
        //需要 nonce 可用
        if ($this->nonce === null) {
            $response = $this->getHttpClient()->head($this->directories[self::DIRECTORY_NEW_NONCE]);
            $this->nonce = $response->getHeaderLine('replay-nonce');
        }
        return [
            'alg'   => 'RS256',
            'jwk'   => $this->getJWKHeader(),
            'nonce' => $this->nonce,
            'url'   => $url
        ];
    }

    /**
     * 获取 KID 信封
     *
     * @param $url
     * @param $kid
     * @return array
     */
    protected function getKID($url): array
    {
        $response = $this->getHttpClient()->head($this->directories[self::DIRECTORY_NEW_NONCE]);
        $nonce = $response->getHeaderLine('replay-nonce');

        return [
            "alg"   => "RS256",
            "kid"   => $this->account->getAccountURL(),
            "nonce" => $nonce,
            "url"   => $url
        ];
    }

    /**
     * 将负载转换为 JWS 格式
     *
     * @param $payload
     * @param $url
     * @return array
     * @throws \Exception
     */
    protected function signPayloadJWK($payload, $url): array
    {
        $payload = is_array($payload) ? str_replace('\\/', '/', json_encode($payload)) : '';
        $payload = Helper::toSafeString($payload);
        $protected = Helper::toSafeString(json_encode($this->getJWK($url)));

        $result = openssl_sign($protected . '.' . $payload, $signature, $this->getAccountKey(), "SHA256");

        if ($result === false) {
            throw new \Exception('Could not sign');
        }

        return [
            'protected' => $protected,
            'payload'   => $payload,
            'signature' => Helper::toSafeString($signature),
        ];
    }

    /**
     * 将负载转换为 KID 格式
     *
     * @param $payload
     * @param $url
     * @return array
     * @throws \Exception
     */
    protected function signPayloadKid($payload, $url): array
    {
        $payload = is_array($payload) ? str_replace('\\/', '/', json_encode($payload)) : '';
        $payload = Helper::toSafeString($payload);
        $protected = Helper::toSafeString(json_encode($this->getKID($url)));

        $result = openssl_sign($protected . '.' . $payload, $signature, $this->getAccountKey(), "SHA256");
        if ($result === false) {
            throw new \Exception('Could not sign');
        }

        return [
            'protected' => $protected,
            'payload'   => $payload,
            'signature' => Helper::toSafeString($signature),
        ];
    }
}
