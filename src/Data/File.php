<?php

namespace Jason\Acme\Data;

class File
{
    /**
     * HTTP-01 验证文件的文件名
     * 等于挑战的 token 值
     * 应部署到 /.well-known/acme-challenge/{filename}
     * @var string
     */
    protected string $filename;

    /**
     * HTTP-01 验证文件的内容
     * 格式为：token + "." + digest（账户 JWK Thumbprint）
     * @var string
     */
    protected string $contents;

    /**
     * File 构造函数
     * 由 Authorization::getFile() 创建
     *
     * @param string $filename 验证文件名（等于挑战 token）
     * @param string $contents 验证文件内容（token + "." + digest）
     */
    public function __construct(string $filename, string $contents)
    {
        $this->contents = $contents;
        $this->filename = $filename;
    }

    /**
     * 返回验证文件名
     * 此文件需部署到服务器 /.well-known/acme-challenge/ 目录下
     *
     * @return string
     */
    public function getFilename(): string
    {
        return $this->filename;
    }

    /**
     * 返回验证文件内容
     * LE 会通过 HTTP GET 读取此文件并与预期内容比对
     *
     * @return string
     */
    public function getContents(): string
    {
        return $this->contents;
    }
}
