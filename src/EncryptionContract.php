<?php declare(strict_types=1);

namespace Wsw\Runbook\Vault;

interface EncryptionContract
{

    public function encrypt(string $plaintext): DataEncrypted;

    public function decrypt(DataEncrypted $dataEncrypted);


}