<?php

namespace Jason\Acme;

use Jason\Acme\Data\Account;
use Jason\Acme\Data\Authorization;
use Jason\Acme\Data\Certificate;
use Jason\Acme\Data\Challenge;
use Jason\Acme\Data\Order;
use Jason\Acme\ClientConfig;
use Jason\Acme\Enum\KeyType;
use Jason\Acme\Exception\AcmeException;
use Jason\Acme\Helper;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\RequestException;
use League\Flysystem\Filesystem;
use Psr\Http\Message\ResponseInterface;

class Client
{
    /**
     * ACME 新账户注册资源路径关键字
     * 用于从 LE 目录 JSON 中获取 newAccount 接口的 URL
     */
    const DIRECTORY_NEW_ACCOUNT = 'newAccount';

    /**
     * ACME replay-nonce 资源路径关键字
     * 每次 JWS 签名都需要一个一次性 nonce 来防止重放攻击
     * 首次通过 HEAD 请求获取，后续从响应头 replay-nonce 中缓存
     */
    const DIRECTORY_NEW_NONCE = 'newNonce';

    /**
     * ACME 新订单资源路径关键字
     * 申请证书前必须先创建一个订单，指定要申请的域名
     */
    const DIRECTORY_NEW_ORDER = 'newOrder';

    /**
     * HTTP-01 验证方式标识
     * LE 通过 HTTP GET 访问 http://<域名>/.well-known/acme-challenge/<token>
     * 验证文件内容是否等于 token.digest，从而证明域名控制权
     * 要求域名 80 端口可访问
     */
    const VALIDATION_HTTP = 'http-01';

    /**
     * DNS-01 验证方式标识
     * LE 通过 DNS 查询 _acme-challenge.<域名> 的 TXT 记录
     * 验证记录值是否等于 base64url(sha256(token.digest))
     * 不依赖 Web 服务器，支持通配符证书（*.example.com）
     */
    const VALIDATION_DNS = 'dns-01';

    /** @var int validate() 轮询间隔基准秒数 */
    const VALIDATION_POLL_DELAY = 15;

    /** @var int selfDNSTest() 轮询间隔基准秒数 */
    const DNS_POLL_DELAY = 45;

    /**
     * ACME replay-nonce 缓存
     * 每次向 LE 成功发送请求后，用响应头中的 replay-nonce 更新此值
     * 下次 JWS 签名时作为 nonce 字段发送给服务器
     * 如果为 null，getJWK()/getKID() 会通过 HEAD 请求获取新的 nonce
     * @var ?string
     */
    protected ?string $nonce;

    /**
     * 当前 LE 账户信息（DTO）
     * 在 init() 中通过 getAccount() 从 LE 获取并创建
     * 包含账户 URL（kid 模式需要）、创建时间、有效状态
     * @var ?Account
     */
    protected ?Account $account;

    /**
     * 账户 RSA 私钥的详细信息
     * 由 loadKeys() 调用 openssl_pkey_get_details() 填充
     * 从中提取 RSA 公钥的 N（模数）和 E（公钥指数）值，用于组装 JWK 头
     * @var array
     */
    protected array $privateKeyDetails;

    /**
     * 账户 RSA 私钥（OpenSSL 资源句柄）
     * 持久化存储在 Flysystem 的 account.pem 文件中
     * 首次使用时若文件不存在则自动生成 4096 位 RSA 密钥
     * 用于 JWS 签名（openssl_sign）和提取公钥信息
     * @var ?\OpenSSLAsymmetricKey
     */
    protected ?\OpenSSLAsymmetricKey $accountKey;

    /**
     * Flysystem 文件系统实例
     * 由构造函数的 config.fs 参数传入
     * 用于持久化存储账户私钥（account.pem）
     * @var Filesystem
     */
    protected Filesystem $filesystem;

    /**
     * LE API 目录索引
     * 在 init() 中通过 GET 请求 LE 根目录返回的 JSON 对象
     * 包含 newAccount、newNonce、newOrder 等接口的完整 URL
     * @var array
     */
    protected array $directories = [];

    /**
     * 预留头字段（当前未使用）
     * @var array
     */
    protected array $header = [];

    /**
     * 密钥指纹（JWK Thumbprint）
     * 对 JWK 头（e、kty、n）做 JSON 序列化 → SHA-256 哈希 → base64url 编码的结果
     * 用于 DNS-01 验证时拼接 TXT 记录值：base64url(sha256(token + "." + digest))
     * 也用于 HTTP-01 验证文件内容的第二部分
     * 懒加载，首次调用 getDigest() 时计算并缓存
     * @var ?string
     */
    protected ?string $digest;

    /**
     * Guzzle HTTP 客户端实例
     * 用于与 LE API 通信
     * base_uri 根据 config.mode 设置为生产或测试环境
     * 支持通过 config.source_ip 绑定源 IP（curl CURLOPT_INTERFACE）
     * 懒加载，首次调用 getHttpClient() 时创建
     * @var ?HttpClient
     */
    protected ?HttpClient $httpClient;

    /**
     * 客户端配置对象
     * @var ClientConfig
     */
    protected ClientConfig $clientConfig;

    /**
     * Client 构造函数
     *
     * 1. 验证配置中必须包含 fs（Filesystem）和 username
     * 2. 调用 init() 启动完整初始化流程：
     *    a. 获取 LE 目录索引
     *    b. 加载或生成账户密钥
     *    c. 同意服务条款（ToS）
     *    d. 获取账户信息
     *
     * @param array|ClientConfig $config 配置数组或 ClientConfig 对象
     */
    public function __construct(array|ClientConfig $config)
    {
        $this->clientConfig = $config instanceof ClientConfig ? $config : ClientConfig::create($config);
        $this->filesystem = $this->clientConfig->getFilesystem();
        $this->init();
    }

    /**
     * 根据 ID 从 LE 重新拉取已创建的订单
     * 通过 KID 模式签名请求，组装 Order DTO 返回
     * 调用链：用户 → isReady() / 直接调用
     *
     * @param string $id 订单号（从 Order::getId() 获取的 URL 中的数字 ID）
     * @return Order 重构的订单对象
     * @throws \Exception LE 请求失败或订单不存在
     */
    public function getOrder(string $id): Order
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
     * 检查订单是否已就绪（ACME 第 3 步：确认订单状态）
     *
     * 在完成所有域名授权验证后，调用此方法检查订单状态是否为 'ready'。
     * 当所有 authorizations 都变为 'valid' 时，LE 将订单状态更新为 'ready'，
     * 表示可以进入最终步骤——申请证书。
     *
     * 调用时机：在 authorize() 完成且所有挑战通过 validate() 验证成功后调用。
     * 上游：createOrder() → authorize() → validate() → isReady()
     * 下游：isReady() 返回 true 后，即可调用 getCertificate() 申请证书
     *
     * @param Order $order 待检查的订单对象（由 createOrder() 返回）
     * @return bool true 表示订单已就绪（所有验证已通过），false 表示等待中
     * @throws \Exception LE 请求失败或订单不存在
     */
    public function isReady(Order $order): bool
    {
        $order = $this->getOrder($order->getId());
        return $order->getStatus() == 'ready';
    }


    /**
     * 创建新订单（ACME 第 1 步：提交域名列表）
     *
     * 向 Let's Encrypt 提交一个订单，指定需要申请证书的所有域名（identifiers）。
     * LE 返回订单对象，其中包含待验证的 authorizations 列表和 finalize URL。
     * 此方法是证书申请流程的起点。
     *
     * 调用时机：账户注册和 ToS 同意完成后，用户需要申请证书时调用。
     * 上游：__construct() 完成 init() 初始化后 → createOrder()
     * 下游：createOrder() 返回的 Order 传给 authorize() 进行域名授权验证
     *
     * @param array $domains 域名列表，如 ['example.com', 'www.example.com']
     * @return Order 新创建的订单对象，包含授权 URL 列表和 finalize URL
     * @throws \Exception LE API 请求失败
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
     * 获取域名授权（ACME 第 2 步：拉取授权及挑战列表）
     *
     * 对订单中的每个域名，向 LE 获取其授权信息（Authorization），
     * 包含该域名下的所有可用验证方式（Challenge），如 HTTP-01 和 DNS-01。
     * 每个 Authorization 包含挑战列表和过期时间。
     *
     * 调用时机：createOrder() 返回订单后立即调用。
     * 上游：createOrder() → authorize()
     * 下游：authorize() 返回的 Authorization 传给 selfTest() 和 validate() 进行验证
     *       用户需根据挑战类型在服务器上部署验证文件（HTTP-01）或 DNS TXT 记录（DNS-01）
     *
     * @param Order $order 由 createOrder() 返回的订单对象
     * @return array|Authorization[] 授权对象数组，每个域名一个，包含该域名的所有挑战
     * @throws \Exception LE 请求失败
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

            $challenges = [];
            foreach ($data['challenges'] as $challengeData) {
                $challenges[] = new Challenge(
                    $authorizationURL,
                    $challengeData['type'],
                    $challengeData['status'],
                    $challengeData['url'],
                    $challengeData['token']
                );
            }
            $authorizations[] = new Authorization(
                $data['identifier']['value'],
                $data['expires'],
                $this->getDigest(),
                $challenges
            );
        }

        return $authorizations;
    }

    /**
     * 本地自测域名验证是否已准备好（ACME 第 2.5 步：验证部署正确性）
     *
     * 在正式向 LE 提交验证请求前，本地模拟 LE 的验证请求，
     * 检测服务器上是否已正确部署验证文件（HTTP-01）或 DNS TXT 记录（DNS-01）。
     * 此步骤非 ACME 协议强制要求，但能提前发现部署问题，避免触发 LE 的验证失败计数。
     *
     * 调用时机：authorize() 返回授权信息后、validate() 之前调用。
     * 上游：authorize() → selfTest()
     * 下游：selfTest() 返回 true 后，再调用 validate() 向 LE 提交验证
     *       若返回 false，说明验证资源未正确部署，用户需检查配置后再试
     *
     * @param Authorization $authorization 由 authorize() 返回的授权对象
     * @param string $type 验证类型：Client::VALIDATION_HTTP（HTTP-01）或 Client::VALIDATION_DNS（DNS-01）
     * @param int $maxAttempts 最大重试次数
     * @return bool true 表示本地自测通过，验证资源已就位
     */
    public function selfTest(Authorization $authorization, string $type = self::VALIDATION_HTTP, int $maxAttempts = 15): bool
    {
        if ($type == self::VALIDATION_HTTP) {
            return $this->selfHttpTest($authorization, $maxAttempts);
        } elseif ($type == self::VALIDATION_DNS) {
            return $this->selfDNSTest($authorization, $maxAttempts);
        }
        return false;
    }

    /**
     * 向 LE 提交挑战验证（ACME 第 3 步：请求验证并轮询结果）
     *
     * 向 LE 发送验证请求，告知 LE 可以开始验证域名控制权。
     * LE 会根据挑战类型（HTTP-01/DNS-01）检查验证资源是否就位。
     * 提交后轮询授权状态，直到状态变为 'valid'（通过）或超时。
     * 所有域名的所有挑战都验证通过后，订单状态才会变为 'ready'。
     *
     * 调用时机：selfTest() 通过后，或用户确认验证资源已部署后调用。
     * 上游：authorize() / selfTest() → validate()
     * 下游：validate() 通过后，调用 isReady() 检查订单状态，
     *       所有验证通过后调用 getCertificate() 获取证书
     *
     * @param Challenge $challenge 要验证的挑战对象（从 Authorization 的挑战列表中获取）
     * @param int $maxAttempts 最大轮询次数（每次间隔逐渐缩短）
     * @return bool true 表示 LE 验证通过，false 表示验证失败或超时
     * @throws \Exception LE 请求失败
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
                sleep(ceil(self::VALIDATION_POLL_DELAY / $maxAttempts));
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
        $keyType = $this->getKeyTypeFromConfig();
        $privateKey = Helper::getNewKeyByType($keyType);
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
     * 获取 Let's Encrypt 账户信息
     *
     * 功能：向 ACME 服务器发送 JWK 签名请求（onlyReturnExisting=true）查询当前账户是否存在并激活。
     * 请求路径为 newAccount 目录地址，使用 JWK（而非 KID）模式签名，因为此时还未获得 account URL。
     *
     * 调用时机：
     *   - init() 初始化流程的最后一步，在 loadKeys() 和 tosAgree() 之后执行
     *   - 外部调用方也可直接调用以刷新账户状态
     *
     * 上下游关系：
     *   上游：init() 调用本方法，将结果赋值给 $this->account
     *   下游：调用 request() 发送 HTTP 请求 → 解析响应头 Location（账户 URL）和 JSON body（createdAt、status）
     *         返回 Account DTO 给调用方
     *   内部：account URL 随后通过 $this->account->getAccountURL() 被 getKID() 用于后续所有 KID 模式签名的请求
     *
     * 返回 Account DTO，包含：
     *   - 账户创建时间（createdAt）
     *   - 账户是否有效（status == 'valid'）
     *   - 账户 URL（Location 头）
     *
     * @return Account 账户 DTO
     * @throws \Exception LE 请求失败或响应格式异常
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
     * 获取 ACME API 通信专用的 Guzzle HTTP 客户端（单例，懒加载）
     *
     * 功能：
     *   创建（或复用）一个指向 LE 目录基地址的 Guzzle 客户端实例。
     *   根据 config.mode 决定 base_uri：
     *     - 'live'    → self::DIRECTORY_LIVE（生产环境）
     *     - 'staging' → self::DIRECTORY_STAGING（测试环境）
     *   如果配置了 source_ip，则通过 CURLOPT_INTERFACE 绑定源 IP。
     *
     * 调用时机：
     *   首次调用时实例化，之后返回缓存的 $this->httpClient。
     *   被以下方法调用：
     *     - init()：GET /directory 拉取 LE 目录
     *     - request()：每次与 LE 通信的核心 HTTP 请求方法
     *     - getJWK() / getKID()：HEAD /newNonce 获取 replay-nonce
     *
     * 上下游关系：
     *   上游：request() / init() 调用本方法获取客户端
     *   下游：返回的 HttpClient 实例用于所有与 LE 服务器的网络通信
     *
     * @return HttpClient Guzzle HTTP 客户端实例
     */
    protected function getHttpClient(): HttpClient
    {
        if ($this->httpClient === null) {
            $ca = $this->clientConfig->getCa();
            $mode = $this->clientConfig->getMode();
            
            $config = [
                'base_uri' => $ca->getDirectoryUrl($mode),
            ];
            
            if ($this->clientConfig->getSourceIp() !== null) {
                $config['curl.options']['CURLOPT_INTERFACE'] = $this->clientConfig->getSourceIp();
            }
            
            $this->httpClient = new HttpClient($config);
        }
        return $this->httpClient;
    }

    /**
     * 获取用于自测（self-test）的 Guzzle HTTP 客户端（每次都新建实例）
     *
     * 功能：
     *   创建一个专用于域名授权验证自测的 HTTP 客户端。与 getHttpClient() 不同：
     *   - 不指向 LE API，而是直接访问目标域名（HTTP-01 验证）或 DNS API（DNS-01 验证）
     *   - 跳过 SSL 验证（verify=false），因为自测访问的是用户自己的服务器而非 LE
     *   - 设置超时：10s 超时，3s 连接超时
     *   - 允许跟随重定向
     *
     * 调用时机：
     *   仅在 selfHttpTest() 中调用，每次自测轮询都会创建新实例
     *
     * 上下游关系：
     *   上游：selfHttpTest() 调用本方法获取客户端
     *   下游：返回的 HttpClient 用于 GET 请求目标域名的 .well-known/acme-challenge/<token> 路径
     *
     * @return HttpClient 用于自测的 Guzzle 客户端
     */
    protected function getSelfTestClient(): HttpClient
    {
        return new HttpClient([
            'verify'          => false,
            'timeout'         => 10,
            'connect_timeout' => 3,
            'allow_redirects' => true,
        ]);
    }

    /**
     * HTTP-01 自测：验证目标域名的 HTTP 文件是否已正确部署
     *
     * 功能：
     *   在向 LE 提交验证之前，本地先自行检查目标域名能否通过 HTTP 访问到正确的验证文件。
     *   尝试 GET http://<域名>/.well-known/acme-challenge/<filename>，将响应体与预期的 file contents 比对。
     *   如果内容一致，说明 Web 服务器已正确配置验证文件，LE 验证大概率也能通过。
     *
     * 验证逻辑（对应 VALIDATION_HTTP 即 http-01）：
     *   1. 从 Authorization 获取待验证文件信息（getFile()）
     *   2. 用 getSelfTestClient() 访问 http://域名/.well-known/acme-challenge/文件名
     *   3. 比对响应内容是否等于期望的 file contents
     *   4. 如果 RequestException 或内容不匹配，sleep 后重试，最多 maxAttempts 次
     *
     * 调用时机：
     *   由 public 方法 selfTest(Authorization, VALIDATION_HTTP) 调用
     *
     * 上下游关系：
     *   上游：selfTest() 根据验证类型分发调用本方法
     *   下游：调用 getSelfTestClient() 获取 HTTP 客户端 → GET 目标 URL
     *         尝试从 Authorization::getFile() 获取 File DTO
     *   返回值：true（自测通过）/ false（自测失败或文件信息不完整）
     *
     * @param Authorization $authorization 授权对象，包含域名和验证文件信息
     * @param int $maxAttempts 最大重试次数（默认 15）
     * @return bool true=自测通过，false=自测失败
     */
    protected function selfHttpTest(Authorization $authorization, int $maxAttempts): bool
    {
        do {
            $maxAttempts--;
            try {
                $file = $authorization->getFile();
                if ($file === false) {
                    return false;
                }

                $response = $this->getSelfTestClient()->request(
                    'GET',
                    'http://' . $authorization->getDomain() . '/.well-known/acme-challenge/' .
                    $file->getFilename()
                );
                $contents = (string)$response->getBody();
                if ($contents == $file->getContents()) {
                    return true;
                }
            } catch (RequestException $e) {
            }
        } while ($maxAttempts > 0);

        return false;
    }

    /**
     * DNS-01 自测：通过 Cloudflare DNS-over-HTTPS API 验证 TXT 记录是否已正确部署
     *
     * 功能：
     *   在向 LE 提交验证之前，本地先自行查询 _acme-challenge.<域名> 的 TXT 记录是否已生效。
     *   使用 Cloudflare 的公共 DNS-over-HTTPS 服务（cloudflare-dns.com/dns-query）执行 DNS 查询，
     *   将返回的 TXT 记录值与 Authorization 中预期的 txt record value 比对。
     *
     * 验证逻辑（对应 VALIDATION_DNS 即 dns-01）：
     *   1. 从 Authorization 获取 TXT 记录信息（getTxtRecord()）
     *   2. 用 getSelfTestDNSClient() 向 cloudflare-dns.com 发起 DNS-over-HTTPS 查询
     *   3. 遍历响应中的 Answer 数组，比对各条 TXT 记录的 data 值
     *   4. 如果未匹配，sleep 后重试（每次等待 45/maxAttempts 秒），最多 maxAttempts 次
     *
     * 调用时机：
     *   由 public 方法 selfTest(Authorization, VALIDATION_DNS) 调用
     *
     * 上下游关系：
     *   上游：selfTest() 根据验证类型分发调用本方法
     *   下游：调用 getSelfTestDNSClient() 获取 DNS-over-HTTPS 客户端
     *         尝试从 Authorization::getTxtRecord() 获取 Record DTO
     *   返回值：true（DNS 记录已生效）/ false（未生效或记录信息不完整）
     *
     * 注意：
     *   本方法依赖 Cloudflare 的公共 DNS 服务，不适用于内网或自定义 DNS 环境。
     *   由于 DNS 传播有延迟，每次重试间隔比 HTTP 自测更长。
     *
     * @param Authorization $authorization 授权对象，包含域名和 TXT 记录信息
     * @param int $maxAttempts 最大重试次数（默认 15）
     * @return bool true=自测通过，false=自测失败
     */
    protected function selfDNSTest(Authorization $authorization, int $maxAttempts): bool
    {
        do {
            $record = $authorization->getTxtRecord();
            if ($record === false) {
                return false;
            }

            $response = $this->getSelfTestDNSClient()->get(
                '/dns-query',
                [
                    'query' => [
                        'name' => $record->getName(),
                        'type' => 'TXT'
                    ]
                ]
            );
            $data = json_decode((string)$response->getBody(), true);
            if (isset($data['Answer'])) {
                foreach ($data['Answer'] as $result) {
                    if (trim($result['data'], "\"") == $record->getValue()) {
                        return true;
                    }
                }
            }
            if ($maxAttempts > 1) {
                sleep(ceil(self::DNS_POLL_DELAY / $maxAttempts));
            }
            $maxAttempts--;
        } while ($maxAttempts > 0);

        return false;
    }

    /**
     * 返回预配置的 Cloudflare DNS API 客户端
     * @return HttpClient
     */
    protected function getSelfTestDNSClient(): HttpClient
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
    protected function init(): void
    {
        //从 LE API 加载目录
        $response = $this->getHttpClient()->get('/directory');
        $result = json_decode((string)$response->getBody(), true);
        $this->directories = $result;

        //准备 LE 账户
        $this->loadKeys();
        $this->tosAgree();
        $this->account = $this->getAccount();
    }

    protected function loadKeys(): void
    {
        //确保私钥已就位
        if ($this->getFilesystem()->has($this->getPath('account.pem')) === false) {
            $keyType = $this->getKeyTypeFromConfig();
            
            $this->getFilesystem()->write(
                $this->getPath('account.pem'),
                Helper::getNewKeyByType($keyType)
            );
        }
        $this->accountKey = openssl_pkey_get_private(
            $this->getFilesystem()->read($this->getPath('account.pem'))
        );
        if ($this->accountKey === false) {
            throw new \RuntimeException('Could not parse account private key');
        }
        $this->privateKeyDetails = openssl_pkey_get_details($this->accountKey);
    }

    /**
     * 从配置中获取密钥类型
     *
     * @return KeyType
     */
    protected function getKeyTypeFromConfig(): KeyType
    {
        return $this->clientConfig->getKeyType();
    }

    /**
     * 同意服务条款
     *
     * @throws \Exception
     */
    protected function tosAgree(): void
    {
        $this->request(
            $this->getUrl(self::DIRECTORY_NEW_ACCOUNT),
            $this->signPayloadJWK(
                [
                    'contact'              => [
                        'mailto:' . $this->clientConfig->getUsername(),
                    ],
                    'termsOfServiceAgreed' => true,
                ],
                $this->getUrl(self::DIRECTORY_NEW_ACCOUNT)
            )
        );
    }

    /**
     * 获取格式化的文件存储路径
     *
     * 作用：根据用户名和 basePath 配置，拼接出账户私钥等文件在 Flysystem 中的完整存储路径。
     * 调用时机：loadKeys() 中读写 account.pem 时调用。
     * 上下游关系：上游依赖 getOption('username') 和 getOption('basePath')；
     *           下游输出路径供 getFilesystem()->has() / write() / read() 使用。
     * 在 JWS 流程中的角色：属于配置管理层，确保账户私钥持久化路径正确，
     *           间接保障 JWS 签名时 getAccountKey() 能正常加载私钥。
     *
     * @param string|null $path  文件相对路径（如 'account.pem'），为 null 时只返回目录路径
     * @return string            完整的文件系统路径
     */
    protected function getPath(?string $path = null): string
    {
        $userDirectory = preg_replace('/[^a-z0-9]+/', '-', strtolower($this->clientConfig->getUsername()));

        return $this->clientConfig->getBasePath()
            . DIRECTORY_SEPARATOR . $userDirectory . ($path === null ? '' : DIRECTORY_SEPARATOR . $path);
    }

    /**
     * 返回 Flysystem 文件系统实例
     *
     * 作用：返回构造函数中注入的 Flysystem 实例，提供文件读写能力。
     * 调用时机：loadKeys() 中检测/写入/读取 account.pem 时频繁调用。
     * 上下游关系：上游由构造函数通过 config.fs 注入；
     *           下游被 getPath() + getFilesystem() 组合使用，
     *           完成私钥文件的持久化存储与加载，是 JWS 签名密钥链条的存储层基础。
     * 在 JWS 流程中的角色：属于配置管理层，保障 RSA 账户私钥的持久化存取。
     *
     * @return Filesystem
     */
    protected function getFilesystem(): Filesystem
    {
        return $this->filesystem;
    }

    /**
     * 获取配置选项
     * 上下游关系：上游由 __construct($config) 注入配置对象；
     *           下游通过 $this->clientConfig 直接访问类型化的 getter。
     */

    /**
     * 返回 Flysystem 文件系统实例
     *   下游输出被 Challenge 验证和自测方法引用。
     * 在 JWS 流程中的角色：属于 JWS 签名辅助层（不直接参与签名，但生成验证挑战必需的材料）。
     *       首次调用时通过懒加载缓存到 $this->digest，避免重复计算。
     *
     * @return string  base64url 编码的 SHA-256 JWK Thumbprint
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
     * 向 LE API 发送 HTTP 请求（核心请求执行器）
     *
     * 作用：执行实际 HTTP 请求，统一设置 Content-Type 为 application/jose+json，
     *       发送 JWS 签名后的 POST 请求体，并从响应头中提取并缓存 replay-nonce。
     * 调用时机：所有需要与 LE 通信的地方——
     *   - init() 中拉取目录
     *   - tosAgree() 中同意服务条款
     *   - getAccount() 中拉取账户信息
     *   - createOrder() / getOrder() / authorize() / validate() / getCertificate()
     *     中提交各种 ACME 操作
     * 上下游关系：
     *   上游：调用方传入已签名的 payload（由 signPayloadJWK / signPayloadKid 产出）和请求 URL；
     *   下游：响应的 replay-nonce 被缓存到 $this->nonce，供下一次 getJWK() / getKID() 使用；
     *        响应体 JSON 被各调用方解析为 DTO。
     * 在 JWS 流程中的角色：JWS 签名链路的最终发送端——
     *       将 signPayloadJWK/signPayloadKid 构建的 JWS 对象序列化为 JSON 发出，
     *       并维护 nonce 生命周期，是 JWS 请求-响应闭环的关键节点。
     *
     * @param string $url     LE API 接口完整 URL
     * @param array  $payload JWS 签名后的请求体（含 protected / payload / signature 三字段）
     * @param string $method  HTTP 方法（默认 POST，ACME 要求绝大多数接口使用 POST）
     * @return ResponseInterface LE 返回的 HTTP 响应
     */
    protected function request(string $url, array $payload = [], string $method = 'POST'): ResponseInterface
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
     * @param string $directory
     *
     * @return string
     * @throws \Exception
     */
    protected function getUrl(string $directory): string
    {
        if (isset($this->directories[$directory])) {
            return $this->directories[$directory];
        }

        throw new AcmeException('Invalid directory: ' . $directory . ' not listed');
    }


    /**
     * 获取密钥
     *
     * @return \OpenSSLAsymmetricKey
     * @throws \Exception
     */
    protected function getAccountKey(): \OpenSSLAsymmetricKey
    {
        if ($this->accountKey === null) {
            $this->accountKey = openssl_pkey_get_private(
                $this->getFilesystem()->read($this->getPath('account.pem'))
            );
            if ($this->accountKey === false) {
                throw new \RuntimeException('Could not parse account private key');
            }
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
     * @param string $url
     * @return array
     * @throws \Exception
     */
    protected function getJWK(string $url): array
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
     * @param string $url
     * @return array
     */
    protected function getKID(string $url): array
    {
        if ($this->nonce === null) {
            $response = $this->getHttpClient()->head($this->directories[self::DIRECTORY_NEW_NONCE]);
            $this->nonce = $response->getHeaderLine('replay-nonce');
        }

        return [
            'alg'   => 'RS256',
            'kid'   => $this->account->getAccountURL(),
            'nonce' => $this->nonce,
            'url'   => $url
        ];
    }

    /**
     * 将负载转换为 JWS 格式
     *
     * @param array|null $payload
     * @param string $url
     * @return array
     * @throws \Exception
     */
    protected function signPayloadJWK(?array $payload, string $url): array
    {
        $payload = is_array($payload) ? str_replace('\\/', '/', json_encode($payload)) : '';
        $payload = Helper::toSafeString($payload);
        $protected = Helper::toSafeString(json_encode($this->getJWK($url)));

        $result = openssl_sign($protected . '.' . $payload, $signature, $this->getAccountKey(), "SHA256");

        if ($result === false) {
            throw new AcmeException('Could not sign');
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
     * @param array|null $payload
     * @param string $url
     * @return array
     * @throws \Exception
     */
    protected function signPayloadKid(?array $payload, string $url): array
    {
        $payload = is_array($payload) ? str_replace('\\/', '/', json_encode($payload)) : '';
        $payload = Helper::toSafeString($payload);
        $protected = Helper::toSafeString(json_encode($this->getKID($url)));

        $result = openssl_sign($protected . '.' . $payload, $signature, $this->getAccountKey(), "SHA256");
        if ($result === false) {
            throw new AcmeException('Could not sign');
        }

        return [
            'protected' => $protected,
            'payload'   => $payload,
            'signature' => Helper::toSafeString($signature),
        ];
    }
}
