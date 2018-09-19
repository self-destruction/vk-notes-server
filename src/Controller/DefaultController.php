<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Annotation\Route;

/**
 * @Route("/api")
 */
class DefaultController extends AbstractController
{
    private const SECRET_KEY = 'very_secret_key';

    /**
     * @Route("/encrypt/{token}", methods={"GET"})
     */
    public function encrypt($token)
    {
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Headers: Content-Type');
        header('Access-Control-Allow-Credentials: true');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');

        $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
        $iv = openssl_random_pseudo_bytes($ivlen);
        $ciphertext_raw = openssl_encrypt($token, $cipher, self::SECRET_KEY, $options=OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac('sha256', $ciphertext_raw, self::SECRET_KEY, $as_binary=true);
        $cipherText = base64_encode( $iv.$hmac.$ciphertext_raw );

        return $this->json([
            'cipher' => $cipherText,
        ]);
    }

    /**
     * @Route("/decrypt/{cipher}", methods={"GET"})
     */
    public function decrypt($cipher)
    {
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Credentials: true');
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');

        $c = base64_decode($cipher);
        $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
        $iv = substr($c, 0, $ivlen);
        $hmac = substr($c, $ivlen, $sha2len=32);
        $ciphertext_raw = substr($c, $ivlen+$sha2len);
        $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, self::SECRET_KEY, $options=OPENSSL_RAW_DATA, $iv);
        $calcmac = hash_hmac('sha256', $ciphertext_raw, self::SECRET_KEY, $as_binary=true);
        $originalToken = hash_equals($hmac, $calcmac) ? $original_plaintext : null;

        return $this->json([
            'token' => $originalToken,
        ]);
    }
}