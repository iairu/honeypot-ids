<?php

declare (strict_types=1);
namespace WpifyWooDeps\DASPRiD\Enum;

use WpifyWooDeps\DASPRiD\Enum\Exception\CloneNotSupportedException;
use WpifyWooDeps\DASPRiD\Enum\Exception\SerializeNotSupportedException;
use WpifyWooDeps\DASPRiD\Enum\Exception\UnserializeNotSupportedException;
final class NullValue
{
    /**
     * @var self
     */
    private static $instance;
    private function __construct()
    {
    }
    public static function instance(): self
    {
        return self::$instance ?: self::$instance = new self();
    }
    /**
     * Forbid cloning enums.
     *
     * @throws CloneNotSupportedException
     */
    final public function __clone()
    {
        throw new CloneNotSupportedException();
    }
    /**
     * Forbid serializing enums.
     *
     * @throws SerializeNotSupportedException
     */
    final public function __sleep(): array
    {
        throw new SerializeNotSupportedException();
    }
    /**
     * Forbid serializing enums.
     *
     * @throws SerializeNotSupportedException
     */
    final public function __serialize(): array
    {
        throw new SerializeNotSupportedException();
    }
    /**
     * Forbid unserializing enums.
     *
     * @throws UnserializeNotSupportedException
     */
    final public function __wakeup(): void
    {
        throw new UnserializeNotSupportedException();
    }
    /**
     * Forbid unserializing enums.
     *
     * @throws UnserializeNotSupportedException
     */
    final public function __unserialize($arg): void
    {
        throw new UnserializeNotSupportedException();
    }
}
