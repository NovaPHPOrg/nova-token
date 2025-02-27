<?php

/*
 * Copyright (c) 2025. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
 * Morbi non lorem porttitor neque feugiat blandit. Ut vitae ipsum eget quam lacinia accumsan.
 * Etiam sed turpis ac ipsum condimentum fringilla. Maecenas magna.
 * Proin dapibus sapien vel ante. Aliquam erat volutpat. Pellentesque sagittis ligula eget metus.
 * Vestibulum commodo. Ut rhoncus gravida arcu.
 */

declare(strict_types=1);

namespace nova\plugin\token;

/**
 * Class NovaToken
 * 一个基于AES-256-CBC的数据加密解密类
 * 包含时间戳验证、签名验证，可选择加密或仅验证签名
 * @package nova\plugin\token
 */
class NovaToken
{
    /**
     * 获取签名
     * @param  string $data 待签名数据
     * @param  string $key  密钥
     * @return string 返回签名
     */
    private static function sign(string $data, string $key): string
    {
        return hash_hmac('sha256', $data, $key, true);
    }

    /**
     * 对密钥进行处理，确保其长度为32字节
     * @param  string $key 原始密钥
     * @return string 返回处理后的32字节密钥
     */
    private static function processKey(string $key): string
    {
        if (strlen($key) < 32) {
            return str_pad($key, 32, "\0");  // 补充0x00
        }
        return substr($key, 0, 32);  // 截取32字节
    }

    /**
     * 解码数据
     * @param  string     $token     加密令牌
     * @param  string     $key       密钥
     * @param  bool       $encrypted 是否使用加密模式（默认为true）
     * @return array|bool 解密成功返回数组，失败返回false
     */
    public static function decode(string $token, string $key, bool $encrypted = true): array|bool
    {
        // 处理密钥
        $key = self::processKey($key);

        $token = base64_decode($token);
        $jsonLength = strlen($token) - 32; // 32字节的签名
        $data = substr($token, 0, $jsonLength); // 获取数据部分
        $sign = substr($token, $jsonLength); // 获取签名部分

        // 验证签名
        if (hash_equals(self::sign($data, $key), $sign)) {
            if ($encrypted) {
                // 加密模式下，解密数据
                $data = openssl_decrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, substr($key, 0, 16));
            }

            $json = json_decode($data, true);
            // 验证时间戳（以秒为单位）
            if (isset($json['t'])) {
                if ($json['t'] >= time()) {
                    return $json;
                }

            } else {
                return $json;
            }
        }
        return false;
    }

    /**
     * 编码数据
     * @param  array  $json      待加密的数组
     * @param  string $key       密钥
     * @param  int    $timeout   超时时间（分钟），默认0分钟，不限制时间
     * @param  bool   $encrypted 是否加密（默认为true）
     * @return string 加密或签名后的令牌
     */
    public static function encode(array $json, string $key, int $timeout = 0, bool $encrypted = true): string
    {
        // 处理密钥
        $key = self::processKey($key);

        // 设置时间戳（当前时间 + 超时时间，转换为秒）
        if ($timeout > 0) {
            $json['t'] =  time() + ($timeout * 60);
        }

        $data = json_encode($json);

        if ($encrypted) {
            // 加密数据
            $data = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, substr($key, 0, 16));
        }

        // 生成签名
        $sign = self::sign($data, $key);
        // 返回Base64编码后的数据和签名
        return base64_encode($data . $sign);
    }
}
