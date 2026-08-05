<?php

namespace WpifyWooDeps;

/**
 * Class ActionScheduler_NullLogEntry
 */
class ActionScheduler_NullLogEntry extends \ActionScheduler_LogEntry
{
    /**
     * Construct.
     *
     * @param string $action_id Action ID.
     * @param string $message   Log entry.
     */
    public function __construct($action_id = '', $message = '')
    {
        // nothing to see here.
    }
}
/**
 * Class ActionScheduler_NullLogEntry
 */
\class_alias('WpifyWooDeps\ActionScheduler_NullLogEntry', 'ActionScheduler_NullLogEntry', \false);
