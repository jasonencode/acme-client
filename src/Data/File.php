<?php

namespace Jason\Acme\Data;

class File
{

    /**
     * @var string
     */
    protected $filename;

    /**
     * @var string
     */
    protected $contents;

    /**
     * File 构造函数
     * @param string $filename
     * @param string $contents
     */
    public function __construct(string $filename, string $contents)
    {
        $this->contents = $contents;
        $this->filename = $filename;
    }

    /**
     * 返回 HTTP 验证的文件名
     * @return string
     */
    public function getFilename(): string
    {
        return $this->filename;
    }

    /**
     * 返回 HTTP 验证的文件内容
     * @return string
     */
    public function getContents(): string
    {
        return $this->contents;
    }
}
