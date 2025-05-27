<?php declare(strict_types=1);

namespace Wsw\Runbook\Vault;

use Wsw\Runbook\Contract\Vault\DataEncryptedContract;

final class DataEncrypted implements DataEncryptedContract
{
    private $iv;
    private $ciphertext;

    public function __construct(string $iv, string $ciphertext)
    {
        $this->iv = $iv;
        $this->ciphertext = $ciphertext;
    }

    public function getIv(): string
    {
        return $this->iv;
    }

    public function getCiphertext(): string
    {
        return $this->ciphertext;
    }

    public function toArray(): array
    {
        return [
            'iv' => $this->getIv(),
            'ciphertext' => $this->getCiphertext()
        ];
    }
}
