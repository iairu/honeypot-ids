<?php

namespace WpifyWooDeps\Wpify\Log;

use WpifyWooDeps\Psr\Log\AbstractLogger;
use WpifyWooDeps\Psr\Log\LoggerInterface;
class Log extends AbstractLogger implements LoggerInterface
{
    private $channel;
    private $handlers;
    private $menu_args;
    private $wc_logger = null;
    private $use_wc_logger = \false;
    /**
     * Detailed debug information
     */
    public const DEBUG = 100;
    /**
     * Interesting events
     * Examples: User logs in, SQL logs.
     */
    public const INFO = 200;
    /**
     * Uncommon events
     */
    public const NOTICE = 250;
    /**
     * Exceptional occurrences that are not errors
     * Examples: Use of deprecated APIs, poor use of an API,
     * undesirable things that are not necessarily wrong.
     */
    public const WARNING = 300;
    /**
     * Runtime errors
     */
    public const ERROR = 400;
    /**
     * Critical conditions
     * Example: Application component unavailable, unexpected exception.
     */
    public const CRITICAL = 500;
    /**
     * Action must be taken immediately
     * Example: Entire website down, database unavailable, etc.
     */
    public const ALERT = 550;
    /**
     * Urgent alert.
     */
    public const EMERGENCY = 600;
    public function __construct(string $channel, array $handlers = [], array $menu_args = [])
    {
        $this->channel = $channel;
        $this->handlers = $handlers;
        $this->menu_args = $menu_args;
        if (function_exists('wc_get_logger')) {
            $this->wc_logger = wc_get_logger();
        }
        $this->use_wc_logger = apply_filters('wpify_log_use_wc_logger', $this->wc_logger && empty($this->menu_args['parent_slug']), $channel);
        $levels = ['debug', 'info', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency'];
        foreach ($levels as $level) {
            add_action("wpify_log_{$this->channel}_{$level}", [$this, $level], 10, 2);
        }
        add_filter('wpify_logs', function ($logs) {
            $logs[$this->channel] = $this;
            // Expose this instance to Tools
            return $logs;
        });
        $tools_slug = 'wpify';
        if (isset($this->menu_args['menu_slug']) && 'wpify-logs' !== $this->menu_args['menu_slug']) {
            $tools_slug = $this->menu_args['menu_slug'];
        }
        if (!$this->use_wc_logger && !apply_filters($tools_slug . '_log_tools_initialized', \false)) {
            add_filter($tools_slug . '_log_tools_initialized', '__return_true');
            new Tools($this->menu_args);
        }
    }
    public function debug($message, array $data = []): void
    {
        $this->log('debug', $message, $data);
    }
    public function info($message, array $data = []): void
    {
        $this->log('info', $message, $data);
    }
    public function notice($message, array $data = []): void
    {
        $this->log('notice', $message, $data);
    }
    public function warning($message, array $data = []): void
    {
        $this->log('warning', $message, $data);
    }
    public function error($message, array $data = []): void
    {
        $this->log('error', $message, $data);
    }
    public function critical($message, array $data = []): void
    {
        $this->log('critical', $message, $data);
    }
    public function alert($message, array $data = []): void
    {
        $this->log('alert', $message, $data);
    }
    public function emergency($message, array $data = []): void
    {
        $this->log('emergency', $message, $data);
    }
    public function get_channel(): string
    {
        return $this->channel;
    }
    public function get_handlers(): array
    {
        return $this->handlers;
    }
    public function getHandlers(): array
    {
        return $this->handlers;
    }
    public function log($level, $message, array $context = []): void
    {
        $level_name = $this->normalizeLevelName($level);
        if ($this->wc_logger && $this->use_wc_logger) {
            $ctx = array_merge($context, ['source' => $this->channel]);
            $this->wc_logger->log($level_name, $this->interpolate((string) $message, $context), $ctx);
            return;
        }
        foreach ($this->handlers as $handler) {
            if (method_exists($handler, 'write')) {
                $record = ['message' => (string) $this->interpolate((string) $message, $context), 'context' => $context, 'level' => $this->levelNameToNumber($level_name), 'level_name' => strtoupper($level_name), 'channel' => $this->channel, 'datetime' => date('c'), 'extra' => []];
                $handler->write($record);
            }
        }
    }
    private function normalizeLevelName($level): string
    {
        if (is_int($level)) {
            return $this->levelNumberToName($level);
        }
        $level = strtolower((string) $level);
        $valid = ['debug', 'info', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency'];
        return in_array($level, $valid, \true) ? $level : 'debug';
    }
    private function levelNumberToName(int $level): string
    {
        $map = [self::DEBUG => 'debug', self::INFO => 'info', self::NOTICE => 'notice', self::WARNING => 'warning', self::ERROR => 'error', self::CRITICAL => 'critical', self::ALERT => 'alert', self::EMERGENCY => 'emergency'];
        return $map[$level] ?? 'debug';
    }
    private function levelNameToNumber(string $level): int
    {
        $map = ['debug' => self::DEBUG, 'info' => self::INFO, 'notice' => self::NOTICE, 'warning' => self::WARNING, 'error' => self::ERROR, 'critical' => self::CRITICAL, 'alert' => self::ALERT, 'emergency' => self::EMERGENCY];
        return $map[strtolower($level)] ?? self::DEBUG;
    }
    private function interpolate(string $message, array $context): string
    {
        if (strpos($message, '{') === \false) {
            return $message;
        }
        $replacements = [];
        foreach ($context as $key => $val) {
            if (is_null($val) || is_scalar($val) || is_object($val) && method_exists($val, '__toString')) {
                $replacements['{' . $key . '}'] = (string) $val;
            } else {
                $replacements['{' . $key . '}'] = json_encode($val);
            }
        }
        return strtr($message, $replacements);
    }
}
