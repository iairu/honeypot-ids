<?php

namespace WpifyWooDeps\Wpify\Log;

class RotatingFileHandler
{
    private $base_path;
    private $max_files;
    private $file_perms;
    public function __construct(string $base_path, int $max_files = 5, int $file_perms = 0660)
    {
        $this->base_path = $base_path;
        $this->max_files = max(1, $max_files);
        $this->file_perms = $file_perms;
    }
    public function get_glob_pattern(): string
    {
        return $this->globPatternFromBase($this->base_path);
    }
    public function write(array $record): void
    {
        $path = $this->dailyPath($this->base_path);
        $this->ensureDir(dirname($path));
        $line = json_encode($record, \JSON_UNESCAPED_UNICODE) . "\n";
        $file_exists = file_exists($path);
        file_put_contents($path, $line, \FILE_APPEND);
        if (!$file_exists) {
            @chmod($path, $this->file_perms);
        }
        $this->rotate();
    }
    private function rotate(): void
    {
        $files = glob($this->get_glob_pattern());
        if (!is_array($files)) {
            return;
        }
        rsort($files);
        // Newest first by date in filename
        $to_delete = array_slice($files, $this->max_files);
        foreach ($to_delete as $old) {
            @unlink($old);
        }
    }
    private function dailyPath(string $base): string
    {
        $ext_pos = strrpos($base, '.log');
        $prefix = $ext_pos !== \false ? substr($base, 0, $ext_pos) : $base;
        return sprintf('%s-%s.log', $prefix, date('Y-m-d'));
    }
    private function globPatternFromBase(string $base): string
    {
        $ext_pos = strrpos($base, '.log');
        $prefix = $ext_pos !== \false ? substr($base, 0, $ext_pos) : $base;
        return sprintf('%s-*.log', $prefix);
    }
    private function ensureDir(string $dir): void
    {
        if (is_dir($dir)) {
            return;
        }
        wp_mkdir_p($dir);
    }
}
