<?php

namespace Jason\Acme\Exception;

/**
 * ACME 客户端运行时异常
 *
 * 在密钥生成、证书解析、JWS 签名、CSR 创建等核心操作失败时抛出。
 * 对应 ACME 协议层面的错误，而非配置错误。
 *
 * @package Jason\Acme\Exception
 */
class AcmeException extends \RuntimeException
{
}