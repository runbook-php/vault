<?php declare(strict_types=1);

namespace Wsw\Runbook\Vault;

use Wsw\Runbook\Contract\Vault\EncryptionContract;
use Wsw\Runbook\Contract\Vault\DataEncryptedContract;

class AES256CBCEncryption implements EncryptionContract
{
    public const IV_BYTES = 16;
    public const CIPHER = 'aes-256-cbc';

    private $key;

    public function __construct(?string $key = null)
    {
        $this->key = $key;
    }

    public function encrypt(string $plaintext): DataEncryptedContract
    {
        $this->validateKey();
        $iv = random_bytes(static::IV_BYTES);
        $ciphertext = openssl_encrypt($plaintext, static::CIPHER, $this->key, OPENSSL_RAW_DATA, $iv);
        return new DataEncrypted(base64_encode($iv), base64_encode($ciphertext));
    }

    public function decrypt(DataEncryptedContract $dataEncrypted)
    {
        $this->validateKey();
        $iv = base64_decode($dataEncrypted->getIv());
        $ciphertext = base64_decode($dataEncrypted->getCiphertext());
        return openssl_decrypt($ciphertext, static::CIPHER, $this->key, OPENSSL_RAW_DATA, $iv);
    }

    private function validateKey(): void
    {
        
        if ($this->key === null) {
            throw new \RuntimeException('Encryption key not found. Please generate or configure the key before using vault features');
        }

        $expectedBytes = 32;
        $varBin = hex2bin($this->key);
        if (strlen($varBin) !== $expectedBytes) {
            throw new \RuntimeException("Invalid encryption key. Expected: {$expectedBytes} bytes, received: " . strlen($varBin) . " bytes.");
        }
    }
}
