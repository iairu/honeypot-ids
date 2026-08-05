<?php

declare (strict_types=1);
namespace WpifyWooDeps\h4kuna\Ares\Exception;

use WpifyWooDeps\h4kuna\Ares\Ares\Core\Data;
use WpifyWooDeps\Psr\Http\Client\ClientExceptionInterface;
final class AdisResponseException extends RuntimeException implements ClientExceptionInterface
{
    public function __construct(public Data $data, ServerResponseException $previous)
    {
        parent::__construct('Validation by Adis failed, you can use $data from ARES only. Fields vat_payer and tin are not valid.', $previous);
    }
    public static function fromServerException(Data $data, ServerResponseException $e): self
    {
        return new self($data, $e);
    }
}
