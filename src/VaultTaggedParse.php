<?php declare(strict_types=1);

namespace Wsw\Runbook\Vault;

use Wsw\Runbook\Contract\TaggedParse\TaggedParseContract;

class VaultTaggedParse implements TaggedParseContract
{
    private $vault;

    public function __construct(Vault $vault)
    {
        $this->vault = $vault;
    }
    public function getName(): string
    {
        return 'Vault';
    }

    public function parse($value)
    {
        return $this->vault->read($value);
    }
}
