<?php

namespace Jason\Acme\Enum;

/**
 * 客户端运行模式枚举
 * 
 * @package Jason\Acme\Enum
 */
enum ClientMode: string
{
    /**
     * 测试环境
     * 
     * 使用测试 CA 颁发的证书，不受浏览器信任，用于开发测试。
     */
    case STAGING = 'staging';

    /**
     * 生产环境
     * 
     * 使用正式 CA 颁发的证书，受浏览器信任，用于生产部署。
     */
    case LIVE = 'live';
}
