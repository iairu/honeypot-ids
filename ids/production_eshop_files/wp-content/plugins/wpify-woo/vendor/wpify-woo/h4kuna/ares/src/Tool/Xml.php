<?php

declare (strict_types=1);
namespace WpifyWooDeps\h4kuna\Ares\Tool;

use WpifyWooDeps\h4kuna\Ares\Exception\ServerResponseException;
use JsonException;
use WpifyWooDeps\Nette\Utils\Json;
use WpifyWooDeps\Psr\Http\Message\ResponseInterface;
use SimpleXMLElement;
use stdClass;
final class Xml
{
    /**
     * @throws ServerResponseException
     */
    public static function toJson(SimpleXMLElement|ResponseInterface $response): stdClass
    {
        if ($response instanceof ResponseInterface) {
            $xml = @simplexml_load_string($response->getBody()->getContents());
        } else {
            $xml = $response;
        }
        if ($xml === \false) {
            throw ServerResponseException::brokenXml();
        }
        try {
            $data = Json::decode(Json::encode($xml));
            assert($data instanceof stdClass);
        } catch (JsonException $e) {
            throw ServerResponseException::fromException($e);
        }
        return $data;
    }
}
