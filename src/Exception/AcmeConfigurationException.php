<?php

namespace Jason\Acme\Exception;

/**
 * ACME 客户端配置异常
 *
 * 在配置不合法（模式、IP 格式、邮箱格式、路径等）时抛出。
 * 通常在 ClientConfig::validate() 或 setter 方法中被触发。
 *
 * @package Jason\Acme\Exception
 */
class AcmeConfigurationException extends \InvalidArgumentException
{
}