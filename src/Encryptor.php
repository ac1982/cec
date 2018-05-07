<?php

/**
 * This file is part of the AC1982/cec.
 *
 * (c) AC <ac@fabtek.cn>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace AC1982\CEC;

class Encryptor
{
    protected $operatorID, $operatorSecret, $aesSecret, $aesIv, $signatureSecret;

    /**
     * Encryptor constructor.
     * @param array $config
     */
    public function __construct(array $config)
    {
        $this->operatorID = $config['operatorID'];
        $this->operatorSecret = $config['operatorSecret'];
        $this->aesSecret = $config['aesSecret'];
        $this->aesIv = $config['aesIv'];
        $this->signatureSecret = $config['signatureSecret'];
    }

    /**
     * Encrypt the message.
     * @param $str
     * @return string
     */
    public function encrypt($str)
    {
        $encrypted = openssl_encrypt($str, 'aes-128-cbc', $this->aesSecret, OPENSSL_RAW_DATA, $this->aesIv);

        return base64_encode($encrypted);
    }

    /**
     * Decrypt the message.
     * @param $encrypted
     * @return bool|string
     */
    public function decrypt($encrypted)
    {
        $cipherText = base64_decode($encrypted, true);
        $decrypted = openssl_decrypt($cipherText, 'aes-128-cbc', $this->aesSecret, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING, $this->aesIv);
        $pad = ord(substr($decrypted, -1));
        if ($pad < 1 || $pad > 32) {
            $pad = 0;
        }

        return substr($decrypted, 0, (strlen($decrypted) - $pad));
    }

    /**
     * @param $encrypted
     * @param $timestamp
     * @param $seq
     * @return string
     */
    public function signature($encrypted, $timestamp, $seq)
    {
        $data = $this->operatorID . $encrypted . $timestamp . $seq;
        $hash = hash_hmac('md5', $data, $this->signatureSecret);

        return strtoupper($hash);
    }
}