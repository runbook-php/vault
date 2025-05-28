<?php declare(strict_types=1);

namespace Wsw\Runbook\Vault;

use League\Flysystem\FilesystemOperator;
use Wsw\Runbook\Contract\Vault\EncryptionContract;

class Vault
{
    private $fileSystemSecret;
    private $encrypt;
    public function __construct(FilesystemOperator $fileSystemSecret, EncryptionContract $encrypt)
    {
        $this->fileSystemSecret = $fileSystemSecret;
        $this->encrypt = $encrypt;
    }

    public function keyGenerate(int $bytes = 32): string 
    {
        return bin2hex(random_bytes($bytes));
    }

    private function getHash(string $secretPath): string
    {
        return hash('sha3-256', $secretPath);
    }

    public function exists(string $secretPath): bool
    {
        $secretPath = $this->normalizedSecretPath($secretPath);
        $this->validateSecretPath($secretPath);
        $secretFileName = $this->getHash($secretPath) . '.json';
        return $this->fileSystemSecret->fileExists($secretFileName);
    }

    public function write(string $secretPath, string $secret)
    {
        $secretPath = $this->normalizedSecretPath($secretPath);
        $this->validateSecretPath($secretPath);
        $secretFileName = $this->getHash($secretPath) . '.json';

        if ($this->fileSystemSecret->fileExists($secretFileName)) {
            throw new \InvalidArgumentException("The secret path '{$secretPath}' already exists. A key with this name is already stored in the vault.");
        }

        $encryptedData = $this->encrypt->encrypt($secret);
        $data = $encryptedData->toArray();
        $data['path'] = $secretPath;

        $this->fileSystemSecret->write($secretFileName, json_encode($data));
    }

    public function read(string $secretPath)
    {
        $secretPath = $this->normalizedSecretPath($secretPath);
        $this->validateSecretPath($secretPath);
        $secretFileName = $this->getHash($secretPath) . '.json';

        if (!$this->fileSystemSecret->fileExists($secretFileName)) {
            throw new \InvalidArgumentException("Key not found for path '{$secretPath}'. Please ensure the secret exists in the vault.");
        }

        $data = json_decode($this->fileSystemSecret->read($secretFileName), true);

        if (!is_array($data) || !isset($data['iv']) || !isset($data['ciphertext']) || empty($data['iv']) || empty($data['ciphertext'])) {
            throw new \RuntimeException("Failed to retrieve the content from secret path '{$secretPath}'. The secret may be missing, corrupted, or inaccessible.");
        }

        $encryptedData = $this->encrypt->decrypt(new DataEncrypted($data['iv'], $data['ciphertext']));
        return $encryptedData;
    }

    public function destroy(string $secretPath): void
    {
        $secretPath = $this->normalizedSecretPath($secretPath);
        $this->validateSecretPath($secretPath);
        $secretFileName = $this->getHash($secretPath) . '.json';

        if (!$this->fileSystemSecret->fileExists($secretFileName)) {
            throw new \InvalidArgumentException("Key not found for path '{$secretPath}'. Please ensure the secret exists in the vault.");
        }

        $this->fileSystemSecret->delete($secretFileName);
        return;
    }

    public function normalizedSecretPath(string $secretPath): string
    {
        $secretPath = mb_strtolower($secretPath);
        $secretPath = '/' . ltrim($secretPath, '/');
        $secretPath = rtrim($secretPath, '/');
        return trim($secretPath);
    }

    private function validateSecretPath(string $path)
    {
        if (!preg_match('/^[a-z0-9\/]+$/', $path)) {
            throw new \InvalidArgumentException("Invalid secret path: '{$path}'. Only lowercase letters (a–z), numbers (0–9), and forward slashes ('/') are allowed.");
        }
    }
}
