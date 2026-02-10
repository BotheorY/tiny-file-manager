<?php
declare(strict_types=1);

const DEBUG_MODE = true;

if (!defined('BT_DEFAULT_PASSWORD')) {
    define('BT_DEFAULT_PASSWORD', '@@admiN6451_');
}

/**
 * Tiny File Manager
 * 
 * A single-file PHP file manager with authentication, CSRF protection,
 * rate limiting, and robust file system operations.
 */

function debugPhpErrorName(int $severity): string
{
    return match ($severity) {
        E_ERROR => 'E_ERROR',
        E_WARNING => 'E_WARNING',
        E_PARSE => 'E_PARSE',
        E_NOTICE => 'E_NOTICE',
        E_CORE_ERROR => 'E_CORE_ERROR',
        E_CORE_WARNING => 'E_CORE_WARNING',
        E_COMPILE_ERROR => 'E_COMPILE_ERROR',
        E_COMPILE_WARNING => 'E_COMPILE_WARNING',
        E_USER_ERROR => 'E_USER_ERROR',
        E_USER_WARNING => 'E_USER_WARNING',
        E_USER_NOTICE => 'E_USER_NOTICE',
        E_RECOVERABLE_ERROR => 'E_RECOVERABLE_ERROR',
        E_DEPRECATED => 'E_DEPRECATED',
        E_USER_DEPRECATED => 'E_USER_DEPRECATED',
        default => 'E_UNKNOWN',
    };
}

function debugFormatBacktrace(array $trace): string
{
    $lines = [];
    $i = 0;
    foreach ($trace as $frame) {
        if (!is_array($frame)) {
            continue;
        }
        $file = $frame['file'] ?? '[internal]';
        $line = $frame['line'] ?? 0;

        $call = '';
        if (isset($frame['class']) && is_string($frame['class'])) {
            $call .= $frame['class'];
            $call .= (isset($frame['type']) && is_string($frame['type'])) ? $frame['type'] : '::';
        }
        if (isset($frame['function']) && is_string($frame['function'])) {
            $call .= $frame['function'];
        } else {
            $call .= '{closure}';
        }
        $call .= '()';

        $lines[] = '#' . $i . ' ' . $file . '(' . $line . '): ' . $call;
        $i++;
    }

    return implode("\n", $lines);
}

function debugLogError(string $message, string $type = 'ERROR', ?string $trace = null): void
{
    if (!DEBUG_MODE) {
        return;
    }

    static $isLogging = false;
    if ($isLogging) {
        return;
    }

    $isLogging = true;
    $lockHandle = null;
    $logHandle = null;

    try {
        $dir = __DIR__;
        if (!is_dir($dir) || !is_writable($dir)) {
            return;
        }

        $logPath = $dir . DIRECTORY_SEPARATOR . 'error_log.txt';
        $lockPath = $dir . DIRECTORY_SEPARATOR . 'error_log.lock';
        $maxBytes = 10 * 1024 * 1024;

        $lockHandle = fopen($lockPath, 'c+');
        if ($lockHandle === false) {
            return;
        }
        if (!flock($lockHandle, LOCK_EX)) {
            return;
        }

        if (file_exists($logPath)) {
            $size = null;
            try {
                $size = filesize($logPath);
            } catch (Throwable) {
                $size = null;
            }

            if (is_int($size) && $size > $maxBytes) {
                $ts = (new DateTimeImmutable('now'))->format('Ymd_His');
                $rotated = $dir . DIRECTORY_SEPARATOR . 'error_log_' . $ts . '.txt';
                $attempt = 0;
                while (file_exists($rotated) && $attempt < 100) {
                    $attempt++;
                    $rotated = $dir . DIRECTORY_SEPARATOR . 'error_log_' . $ts . '_' . $attempt . '.txt';
                }

                try {
                    rename($logPath, $rotated);
                } catch (Throwable) {
                }
            }
        }

        $logHandle = fopen($logPath, 'ab');
        if ($logHandle === false) {
            return;
        }

        try {
            chmod($logPath, 0600);
        } catch (Throwable) {
        }

        if (!flock($logHandle, LOCK_EX)) {
            return;
        }

        $now = (new DateTimeImmutable('now'))->format('Y-m-d H:i:s');
        $entry = '[' . $now . '] ' . $type . ' ' . $message . "\n";
        $entry .= "TRACE:\n" . ($trace ?? '') . "\n";
        $entry .= str_repeat('-', 80) . "\n";

        fwrite($logHandle, $entry);
        fflush($logHandle);
    } catch (Throwable) {
    } finally {
        if (is_resource($logHandle)) {
            flock($logHandle, LOCK_UN);
            fclose($logHandle);
        }
        if (is_resource($lockHandle)) {
            flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
        }
        $isLogging = false;
    }
}

function debugLogThrowable(Throwable $e): void
{
    $type = get_class($e);
    if ($e instanceof ErrorException) {
        $type = 'PHP_' . debugPhpErrorName($e->getSeverity());
    }

    $message = $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine();
    $trace = $e->getTraceAsString();
    debugLogError($message, $type, $trace);
}

function debugSetupErrorLogging(): void
{
    set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
        if ((error_reporting() & $severity) === 0) {
            return false;
        }

        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
        array_shift($trace);
        debugLogError(
            $message . ' in ' . $file . ':' . $line,
            'PHP_' . debugPhpErrorName($severity),
            debugFormatBacktrace($trace),
        );

        return false;
    });

    set_exception_handler(static function (Throwable $e): void {
        debugLogThrowable($e);
        http_response_code(500);
        exit(255);
    });

    register_shutdown_function(static function (): void {
        $last = error_get_last();
        if (!is_array($last)) {
            return;
        }

        $type = (int)($last['type'] ?? 0);
        $fatalTypes = [
            E_ERROR,
            E_PARSE,
            E_CORE_ERROR,
            E_COMPILE_ERROR,
            E_USER_ERROR,
            E_RECOVERABLE_ERROR,
        ];

        if (!in_array($type, $fatalTypes, true)) {
            return;
        }

        $message = is_string($last['message'] ?? null) ? $last['message'] : 'Fatal error';
        $file = is_string($last['file'] ?? null) ? $last['file'] : '';
        $line = is_int($last['line'] ?? null) ? $last['line'] : 0;

        debugLogError(
            $message . ' in ' . $file . ':' . $line,
            'PHP_' . debugPhpErrorName($type),
            null,
        );
    });
}

if (DEBUG_MODE) {
    debugSetupErrorLogging();
}

/**
 * Custom Exception for Application Errors.
 * These exceptions are safe to display to the user (publicMessage).
 */
class AppException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly int $httpStatus = 400,
        public readonly ?string $publicMessage = null
    ) {
        parent::__construct($message);
    }
}

final class ZipErrorCode
{
    public const UNAVAILABLE = 1000;
    public const OPEN_FAILED = 1001;
    public const INVALID_ZIP = 1002;
    public const CORRUPT = 1003;
    public const PASSWORD_REQUIRED = 1004;
    public const WRONG_PASSWORD = 1005;
    public const TRAVERSAL = 1006;
    public const DEST_NOT_WRITABLE = 1007;
    public const DEST_EXISTS = 1008;
    public const IO = 1009;
    public const LOCK_TIMEOUT = 1010;
    public const TOO_LARGE = 1011;
    public const TIMEOUT = 1012;
}

final class ZipOpException extends AppException
{
    public function __construct(
        string $message,
        int $httpStatus,
        ?string $publicMessage,
        public readonly int $errorCode,
        public readonly ?string $detail = null,
    ) {
        parent::__construct($message, httpStatus: $httpStatus, publicMessage: $publicMessage);
    }
}

#[Attribute(Attribute::TARGET_METHOD)]
final class RequiresAuth
{
}

#[Attribute(Attribute::TARGET_METHOD)]
final class RequiresCsrf
{
}

#[Attribute(Attribute::TARGET_METHOD)]
final class RateLimited
{
    public function __construct(
        public readonly string $key,
        public readonly int $limit,
        public readonly int $windowSeconds,
    ) {
    }
}

/**
 * Handles persistence of application state (password hash, lockouts) in a JSON file.
 */
final class NoteStore
{
    private ?array $memoized = null;

    public function __construct(private readonly string $noteFile)
    {
    }

    /** 
     * Reads the note file or initializes it if missing.
     * Uses memoization to avoid redundant disk reads in the same request.
     * 
     * @return array{password_hash:string, failed_attempts:int, first_failed_at:int, lock_until:int, updated_at:int} 
     */
    public function readOrInit(bool $forceReload = false): array
    {
        if (!$forceReload && $this->memoized !== null) {
            return $this->memoized;
        }

        if (!file_exists($this->noteFile)) {
            $pwd = trim((string)BT_DEFAULT_PASSWORD);
            $hash = password_hash($pwd, PASSWORD_BCRYPT);
            if (!is_string($hash)) {
                throw new AppException('Failed to generate initial password hash', httpStatus: 500, publicMessage: 'Server initialization failed.');
            }
            $initial = [
                'password_hash' => $hash,
                'failed_attempts' => 0,
                'first_failed_at' => 0,
                'lock_until' => 0,
                'updated_at' => time(),
            ];
            $this->write($initial);
            return $this->memoized = $initial;
        }

        try {
            $raw = file_get_contents($this->noteFile);
            if ($raw === false) {
                throw new AppException('Cannot read note.dat', httpStatus: 500, publicMessage: 'Server is not ready.');
            }
        } catch (ErrorException $e) {
            throw new AppException('Cannot read note.dat: ' . $e->getMessage(), httpStatus: 500, publicMessage: 'Server is not ready.');
        }

        try {
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new AppException('note.dat is invalid JSON', httpStatus: 500, publicMessage: 'Server is not ready.');
        }

        if (!is_array($decoded)) {
             throw new AppException('note.dat is invalid structure', httpStatus: 500, publicMessage: 'Server is not ready.');
        }

        $hash = $decoded['password_hash'] ?? null;
        if (!is_string($hash) || $hash === '') {
            throw new AppException('note.dat missing password_hash', httpStatus: 500, publicMessage: 'Server is not ready.');
        }

        return $this->memoized = [
            'password_hash' => $hash,
            'failed_attempts' => (int)($decoded['failed_attempts'] ?? 0),
            'first_failed_at' => (int)($decoded['first_failed_at'] ?? 0),
            'lock_until' => (int)($decoded['lock_until'] ?? 0),
            'updated_at' => (int)($decoded['updated_at'] ?? 0),
        ];
    }

    /** 
     * Writes state to the file with exclusive locking.
     * 
     * @param array{password_hash:string, failed_attempts:int, first_failed_at:int, lock_until:int, updated_at:int} $data 
     */
    public function write(array $data): void
    {
        try {
            $payload = json_encode($data, flags: JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
             throw new AppException('Failed to encode note.dat payload', httpStatus: 500, publicMessage: 'Server is not ready.');
        }

        $fp = null;
        try {
            $fp = fopen($this->noteFile, 'c+');
            if ($fp === false) {
                throw new AppException('Cannot open note.dat for writing', httpStatus: 500, publicMessage: 'Server is not ready.');
            }

            if (!flock($fp, LOCK_EX)) {
                throw new AppException('Cannot lock note.dat', httpStatus: 500, publicMessage: 'Server is not ready.');
            }

            if (!ftruncate($fp, 0)) {
                throw new AppException('Cannot truncate note.dat', httpStatus: 500, publicMessage: 'Server is not ready.');
            }

            rewind($fp);
            $len = strlen($payload);
            $written = 0;
            while ($written < $len) {
                $n = fwrite($fp, substr($payload, $written));
                if ($n === false || $n === 0) {
                    throw new AppException('Cannot write note.dat', httpStatus: 500, publicMessage: 'Server is not ready.');
                }
                $written += $n;
            }

            fflush($fp);
        } catch (ErrorException $e) {
            throw new AppException('IO Error writing note.dat: ' . $e->getMessage(), httpStatus: 500, publicMessage: 'Server is not ready.');
        } finally {
            if ($fp) {
                flock($fp, LOCK_UN);
                fclose($fp);
            }
        }
        
        try {
            chmod($this->noteFile, 0600);
        } catch (ErrorException) {
            // Ignore chmod failure on Windows or if not permitted
        }

        $this->memoized = $data;
    }
}

/**
 * Handles authentication, session management, and CSRF protection.
 */
final class Security
{
    public function __construct(
        private readonly NoteStore $noteStore,
        private readonly int $idleTimeoutSeconds,
    ) {
    }

    public function startSession(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            if (!isset($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
                $_SESSION['csrf'] = bin2hex(random_bytes(16));
            }
            return;
        }

        $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (($_SERVER['SERVER_PORT'] ?? '') === '443');

        session_name('SFMSESSID');
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => $this->cookiePath(),
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);

        session_start();

        if (!isset($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
            $_SESSION['csrf'] = bin2hex(random_bytes(16));
        }
    }

    public function enforceIdleTimeout(): void
    {
        $now = time();
        $last = $_SESSION['last_activity'] ?? null;
        if (is_int($last) && ($now - $last) > $this->idleTimeoutSeconds) {
            $this->logout();
            return;
        }

        $_SESSION['last_activity'] = $now;
    }

    public function isAuthed(): bool
    {
        return ($_SESSION['is_authed'] ?? false) === true;
    }

    public function csrfToken(): string
    {
        $token = $_SESSION['csrf'] ?? '';
        return is_string($token) ? $token : '';
    }

    public function requireCsrf(): void
    {
        $sent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf'] ?? '');
        if (!is_string($sent) || $sent === '' || !hash_equals($this->csrfToken(), $sent)) {
            throw new AppException('Invalid CSRF token', httpStatus: 403, publicMessage: 'Request rejected.');
        }
    }

    /** @return array{locked:bool, lock_until:int, remaining:int} */
    public function lockState(): array
    {
        $note = $this->noteStore->readOrInit();
        $now = time();
        $lockUntil = (int)($note['lock_until'] ?? 0);
        $locked = $lockUntil > $now;
        return [
            'locked' => $locked,
            'lock_until' => $lockUntil,
            'remaining' => max(0, $lockUntil - $now),
        ];
    }

    public function attemptLogin(string $password, string $csrf): void
    {

        debugLogError('[Security::attemptLogin] login password: ' . $password . ' csrf: ' . $csrf, 'INFO');  // DEBUG

        if (!hash_equals($this->csrfToken(), $csrf)) {
            throw new AppException('Invalid CSRF token for login', httpStatus: 403, publicMessage: 'Request rejected.');
        }

        $note = $this->noteStore->readOrInit(forceReload: true);

        debugLogError('[Security::attemptLogin] note: ' . print_r($note, true), 'INFO');  // DEBUG

        $now = time();
        $lockUntil = (int)$note['lock_until'];
        if ($lockUntil > $now) {
            throw new AppException('Login locked', httpStatus: 429, publicMessage: 'Invalid password or temporarily locked.');
        }

        $hash = $note['password_hash'];
        if (!password_verify($password, $hash)) {
            $updated = $this->updateFailedAttempts($note);
            $this->noteStore->write($updated);
            throw new AppException('Password mismatch', httpStatus: 401, publicMessage: 'Invalid password or temporarily locked.');
        }

        if (password_needs_rehash($hash, algo: PASSWORD_BCRYPT)) {
            $note['password_hash'] = password_hash($password, algo: PASSWORD_BCRYPT);
        }

        $note['failed_attempts'] = 0;
        $note['first_failed_at'] = 0;
        $note['lock_until'] = 0;
        $note['updated_at'] = $now;
        $this->noteStore->write($note);

        session_regenerate_id(true);
        $_SESSION['is_authed'] = true;
        $_SESSION['last_activity'] = $now;
    }

    public function changePassword(string $current, string $next): void
    {
        if ($current === '') {
            throw new AppException('Empty current password', httpStatus: 400, publicMessage: 'Current password is required.');
        }

        if ($next === '') {
            throw new AppException('Empty new password', httpStatus: 400, publicMessage: 'New password is required.');
        }

        if (strlen($next) < 6) {
            throw new AppException('New password too short', httpStatus: 400, publicMessage: 'New password must be at least 6 characters.');
        }

        $note = $this->noteStore->readOrInit(forceReload: true);
        if (!password_verify($current, $note['password_hash'])) {
            throw new AppException('Current password mismatch', httpStatus: 401, publicMessage: 'Current password is incorrect.');
        }

        if (hash_equals($current, $next)) {
            throw new AppException('New password equals current', httpStatus: 400, publicMessage: 'New password must be different from current password.');
        }

        $note['password_hash'] = password_hash($next, algo: PASSWORD_BCRYPT);
        $note['failed_attempts'] = 0;
        $note['first_failed_at'] = 0;
        $note['lock_until'] = 0;
        $note['updated_at'] = time();
        $this->noteStore->write($note);
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }
    }

    public function logout(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION = [];
            if (ini_get('session.use_cookies')) {
                $params = session_get_cookie_params();
                setcookie(
                    name: session_name(),
                    value: '',
                    expires_or_options: time() - 3600,
                    path: $params['path'] ?? $this->cookiePath(),
                    domain: $params['domain'] ?? '',
                    secure: (bool)($params['secure'] ?? false),
                    httponly: (bool)($params['httponly'] ?? true),
                );
            }
            session_destroy();
        }
    }

    public function rateLimit(string $key, int $limit, int $windowSeconds): void
    {
        $now = time();
        if (!isset($_SESSION['rate']) || !is_array($_SESSION['rate'])) {
            $_SESSION['rate'] = [];
        }

        $bucket = $_SESSION['rate'][$key] ?? null;
        if (!is_array($bucket)) {
            $bucket = ['window_start' => $now, 'count' => 0];
        }

        $windowStart = (int)($bucket['window_start'] ?? $now);
        $count = (int)($bucket['count'] ?? 0);

        if (($now - $windowStart) >= $windowSeconds) {
            $windowStart = $now;
            $count = 0;
        }

        $count++;
        $_SESSION['rate'][$key] = ['window_start' => $windowStart, 'count' => $count];

        if ($count > $limit) {
            throw new AppException('Rate limit exceeded', httpStatus: 429, publicMessage: 'Too many requests. Please wait.');
        }
    }

    private function cookiePath(): string
    {
        $script = $_SERVER['SCRIPT_NAME'] ?? '/';
        if (!is_string($script) || $script === '') {
            $script = '/';
        }

        $script = str_replace('\\', '/', $script);
        if ($script[0] !== '/') {
            $script = '/' . $script;
        }

        $dir = str_replace('\\', '/', dirname($script));
        if ($dir === '.' || $dir === '') {
            $dir = '/';
        }
        if ($dir !== '/') {
            $dir = rtrim($dir, '/');
        }
        if ($dir === '' || $dir[0] !== '/') {
            $dir = '/' . ltrim($dir, '/');
        }

        return $dir === '/' ? '/' : $dir . '/';
    }

    /** @param array{password_hash:string, failed_attempts:int, first_failed_at:int, lock_until:int, updated_at:int} $note */
    private function updateFailedAttempts(array $note): array
    {
        $now = time();
        $first = (int)$note['first_failed_at'];
        $attempts = (int)$note['failed_attempts'];

        $windowSeconds = 10 * 60;
        if ($first <= 0 || ($now - $first) > $windowSeconds) {
            $first = $now;
            $attempts = 0;
        }

        $attempts++;

        $note['first_failed_at'] = $first;
        $note['failed_attempts'] = $attempts;
        $note['updated_at'] = $now;

        $maxAttempts = 8;
        if ($attempts >= $maxAttempts) {
            $note['lock_until'] = $now + (15 * 60);
        }

        return $note;
    }
}

/**
 * Handles all file system operations with strict validation and error handling.
 */
final class FsService
{
    private const NAME_MAX_BYTES = 255;
    private const PATH_MAX_BYTES = 4096;
    private const ZIP_MAX_SECONDS = 1800;

    /** @param array<int, string> $protectedBasenames */
    public function __construct(
        private readonly string $baseDir,
        private readonly array $protectedBasenames,
    ) {
        $baseReal = realpath($this->baseDir);
        if ($baseReal === false || !is_dir($baseReal)) {
            throw new AppException('Invalid base dir', httpStatus: 500, publicMessage: 'Server is not ready.');
        }

        $this->baseDirReal = rtrim($baseReal, DIRECTORY_SEPARATOR);
        $this->allowedRoot = $this->filesystemRoot($this->baseDirReal);
    }

    private readonly string $baseDirReal;
    private readonly string $allowedRoot;

    /** @return array<int, array{name:string,type:string,size:int|null,mtime:int,mtime_iso:string|null}> */
    public function listDir(string $relDir): array
    {
        $abs = $this->resolveExistingDir($relDir);
        try {
            $items = scandir($abs);
            if ($items === false) {
                 throw new AppException('Cannot read directory', httpStatus: 403, publicMessage: 'Cannot read this folder.');
            }
        } catch (ErrorException $e) {
            throw new AppException('Cannot read directory: ' . $e->getMessage(), httpStatus: 403, publicMessage: 'Cannot read this folder.');
        }

        $out = [];
        foreach ($items as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }

            if (in_array($name, $this->protectedBasenames, true)) {
                continue;
            }

            if (str_contains($name, "\0")) {
                continue;
            }

            $childAbs = $abs . DIRECTORY_SEPARATOR . $name;
            if (is_link($childAbs)) {
                continue;
            }

            $isDir = is_dir($childAbs);
            $isFile = is_file($childAbs);
            if (!$isDir && !$isFile) {
                continue;
            }

            $size = null;
            $mtime = 0;
            
            try {
                $stat = stat($childAbs);
                if ($stat) {
                    $mtime = (int)($stat['mtime'] ?? 0);
                    if ($isFile) {
                        $size = (int)($stat['size'] ?? 0);
                    }
                }
            } catch (ErrorException) {
                // Ignore stat errors, use defaults
            }
            
            $dt = DateTimeImmutable::createFromFormat('U', (string)$mtime) ?: null;

            $out[] = [
                'name' => $name,
                'type' => $isDir ? 'dir' : 'file',
                'size' => $size,
                'mtime' => $mtime,
                'mtime_iso' => $dt?->format(DATE_ATOM),
            ];
        }

        usort(
            $out,
            static function (array $a, array $b): int {
                $typeA = $a['type'] ?? '';
                $typeB = $b['type'] ?? '';
                if ($typeA !== $typeB) {
                    return $typeA === 'dir' ? -1 : 1;
                }

                return strcasecmp((string)$a['name'], (string)$b['name']);
            },
        );

        return $out;
    }

    public function canonicalDir(string $relDir): string
    {
        $abs = $this->resolveExistingDir($relDir);
        return $this->absToRelFromBase($abs);
    }

    public function rootRel(): string
    {
        $root = realpath($this->allowedRoot);
        if ($root === false || !is_dir($root)) {
            $root = $this->allowedRoot;
        }
        return $this->absToRelFromBase($root);
    }

    /** @return array{saved_as:string, bytes:int} */
    public function upload(string $relDir, array $file): array
    {
        $absDir = $this->resolveExistingDir($relDir);
        if (!is_writable($absDir)) {
            throw new AppException('Directory not writable', httpStatus: 403, publicMessage: 'This folder is not writable.');
        }

        $error = $file['error'] ?? UPLOAD_ERR_NO_FILE;
        if ($error !== UPLOAD_ERR_OK) {
            $msg = match ((int)$error) {
                UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'Upload is too large.',
                UPLOAD_ERR_PARTIAL => 'Upload was interrupted.',
                UPLOAD_ERR_NO_TMP_DIR => 'Server is missing a temporary folder.',
                UPLOAD_ERR_CANT_WRITE => 'Server cannot write the file.',
                UPLOAD_ERR_EXTENSION => 'Upload blocked by server extension.',
                default => 'No file uploaded.',
            };
            throw new AppException('Upload error: ' . (string)$error, httpStatus: 400, publicMessage: $msg);
        }

        $tmp = $file['tmp_name'] ?? '';
        if (!is_string($tmp) || $tmp === '' || !is_uploaded_file($tmp)) {
            throw new AppException('Invalid upload tmp_name', httpStatus: 400, publicMessage: 'Invalid upload.');
        }

        $name = $file['name'] ?? 'upload';
        if (!is_string($name)) {
            $name = 'upload';
        }

        $safe = $this->sanitizeFilename($name);
        $this->assertUploadAllowed($safe);

        $dest = $this->uniquePath($absDir . DIRECTORY_SEPARATOR . $safe);
        
        try {
            if (!move_uploaded_file($tmp, $dest)) {
                throw new AppException('move_uploaded_file failed', httpStatus: 500, publicMessage: 'Upload failed.');
            }
            chmod($dest, 0640);
        } catch (ErrorException $e) {
            throw new AppException('Upload error: ' . $e->getMessage(), httpStatus: 500, publicMessage: 'Upload failed.');
        }

        return [
            'saved_as' => basename($dest),
            'bytes' => (int)($file['size'] ?? 0),
        ];
    }

    public function mkdir(string $relDir, string $name): void
    {
        $absDir = $this->resolveExistingDir($relDir);
        $base = $this->sanitizeBasename($name);
        $target = $absDir . DIRECTORY_SEPARATOR . $base;
        $this->assertWithinBase($target);

        if (file_exists($target)) {
            throw new AppException('Target exists', httpStatus: 409, publicMessage: 'That name already exists.');
        }

        try {
            if (!mkdir($target, 0750, false)) {
                throw new AppException('mkdir failed', httpStatus: 403, publicMessage: 'Cannot create folder.');
            }
        } catch (ErrorException $e) {
             throw new AppException('mkdir failed: ' . $e->getMessage(), httpStatus: 403, publicMessage: 'Cannot create folder.');
        }
    }

    /** @return array{from:string,to:string,type:'file'|'dir'} */
    public function renameOrMove(string $srcRel, string $dstRel): array
    {
        $srcAbs = $this->resolveExistingPath($srcRel);
        $dstInfo = $this->resolveTargetForWrite($dstRel);
        $dstAbs = $dstInfo['abs'];

        $srcDir = (string)dirname($srcAbs);
        $dstDir = (string)dirname($dstAbs);
        $srcName = (string)basename($srcAbs);
        $dstName = (string)basename($dstAbs);

        if ($srcAbs === $dstAbs) {
            throw new AppException('No-op rename', httpStatus: 400, publicMessage: 'New name matches the current name.');
        }

        $this->assertNameLength($dstName);
        $this->assertPathLength($dstAbs);

        $caseOnly = $srcDir === $dstDir
            && strcasecmp($srcName, $dstName) === 0
            && $srcName !== $dstName;

        if (!$caseOnly) {
            if (file_exists($dstAbs)) {
                throw new AppException('Destination exists', httpStatus: 409, publicMessage: 'That name already exists in the destination folder.');
            }

            $collision = $this->findCaseInsensitiveCollision($dstDir, $dstName);
            if ($collision !== null) {
                throw new AppException('Case-insensitive destination exists', httpStatus: 409, publicMessage: 'That name already exists (case-insensitive conflict).');
            }
        }

        if ($this->isPathWithin($dstAbs, $srcAbs) && is_dir($srcAbs)) {
            throw new AppException('Move into itself', httpStatus: 400, publicMessage: 'Cannot move a folder into itself.');
        }

        $type = is_dir($srcAbs) ? 'dir' : 'file';

        try {
            if ($caseOnly) {
                $tmp = $this->allocateTempSiblingPath($srcDir, $srcName);
                rename($srcAbs, $tmp);
                rename($tmp, $dstAbs);
                return ['from' => $srcRel, 'to' => $dstRel, 'type' => $type];
            }

            if (rename($srcAbs, $dstAbs)) {
                return ['from' => $srcRel, 'to' => $dstRel, 'type' => $type];
            }
        } catch (ErrorException $e) {
            // Fallthrough to cross-device check
        }

        // Check if it was a cross-device error
        $last = error_get_last();
        $msg = is_array($last) && isset($last['message']) && is_string($last['message']) ? $last['message'] : '';
        $looksCrossDevice = stripos($msg, 'cross-device') !== false || stripos($msg, 'Invalid cross-device link') !== false;
        
        // If not cross-device, throw
        if (!$looksCrossDevice) {
             // throw new AppException('rename failed', httpStatus: 403, publicMessage: 'Rename failed.');
             // actually, if rename threw ErrorException, we caught it.
        }

        // Try atomic copy-move
        $this->moveByCopyAtomic($srcAbs, $dstAbs);
        return ['from' => $srcRel, 'to' => $dstRel, 'type' => $type];
    }

    public function copyPath(string $srcRel, string $dstRel): void
    {
        $srcAbs = $this->resolveExistingPath($srcRel);
        $dstAbs = $this->resolveTargetForWrite($dstRel)['abs'];

        if (is_dir($srcAbs)) {
            $this->copyDirRecursive($srcAbs, $dstAbs);
            return;
        }

        try {
            if (!copy($srcAbs, $dstAbs)) {
                throw new AppException('copy failed', httpStatus: 403, publicMessage: 'Copy failed.');
            }
            chmod($dstAbs, 0640);
        } catch (ErrorException $e) {
            throw new AppException('Copy failed: ' . $e->getMessage(), httpStatus: 403, publicMessage: 'Copy failed.');
        }
    }

    public function deletePath(string $rel): void
    {
        $abs = $this->resolveExistingPath($rel);
        if (is_dir($abs)) {
            $this->deleteDirRecursive($abs);
            return;
        }

        try {
            if (!unlink($abs)) {
                throw new AppException('unlink failed', httpStatus: 403, publicMessage: 'Delete failed.');
            }
        } catch (ErrorException $e) {
            throw new AppException('Delete failed: ' . $e->getMessage(), httpStatus: 403, publicMessage: 'Delete failed.');
        }
    }

    public function chmodPath(string $rel, int $mode, bool $recursive): void
    {
        $abs = $this->resolveExistingPath($rel);
        if (is_dir($abs) && $recursive) {
            $this->chmodDirRecursive($abs, $mode);
            return;
        }

        try {
            if (!chmod($abs, $mode)) {
                throw new AppException('chmod failed', httpStatus: 403, publicMessage: 'Permission change failed.');
            }
        } catch (ErrorException $e) {
             throw new AppException('Permission change failed: ' . $e->getMessage(), httpStatus: 403, publicMessage: 'Permission change failed.');
        }
    }

    /** @return array{abs:string, name:string, size:int, mime:string} */
    public function resolveDownload(string $rel): array
    {
        $abs = $this->resolveExistingPath($rel);
        if (!is_file($abs)) {
            throw new AppException('Not a file', httpStatus: 400, publicMessage: 'Not a file.');
        }

        if (!is_readable($abs)) {
            throw new AppException('File not readable', httpStatus: 403, publicMessage: 'File not readable.');
        }

        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime = $finfo->file($abs);
        if (!is_string($mime) || $mime === '') {
            $mime = 'application/octet-stream';
        }

        $size = 0;
        try {
            $size = (int)filesize($abs);
        } catch (ErrorException) {
            $size = 0;
        }

        return [
            'abs' => $abs,
            'name' => basename($abs),
            'size' => $size,
            'mime' => $mime,
        ];
    }

    private function resolveExistingDir(string $relDir): string
    {
        $rel = $this->normalizeRel($relDir);
        $abs = $this->baseDirReal . ($rel === '' ? '' : DIRECTORY_SEPARATOR . $rel);

        $real = realpath($abs);
        if ($real === false || !is_dir($real)) {
            throw new AppException('Directory not found', httpStatus: 404, publicMessage: 'Folder not found.');
        }

        $this->assertWithinBase($real);
        $this->assertNoSymlinkPath($real);

        return $real;
    }

    private function resolveExistingPath(string $rel): string
    {
        $relNorm = $this->normalizeRel($rel);
        if ($relNorm === '') {
            throw new AppException('Empty path', httpStatus: 400, publicMessage: 'Invalid path.');
        }

        $abs = $this->baseDirReal . DIRECTORY_SEPARATOR . $relNorm;
        $real = realpath($abs);
        if ($real === false || !file_exists($real)) {
            throw new AppException('Path not found', httpStatus: 404, publicMessage: 'Not found.');
        }

        if (in_array(basename($real), $this->protectedBasenames, true)) {
            throw new AppException('Protected path blocked', httpStatus: 403, publicMessage: 'This item is protected.');
        }

        if (is_link($real)) {
            throw new AppException('Symlink blocked', httpStatus: 403, publicMessage: 'This item is blocked.');
        }

        $this->assertWithinBase($real);
        $this->assertNoSymlinkPath($real);

        return $real;
    }

    /** @return array{abs:string,parent:string,name:string} */
    private function resolveTargetForWrite(string $rel): array
    {
        $relNorm = $this->normalizeRel($rel);
        if ($relNorm === '') {
            throw new AppException('Empty target path', httpStatus: 400, publicMessage: 'Invalid target path.');
        }

        $abs = $this->baseDirReal . DIRECTORY_SEPARATOR . $relNorm;
        $parent = dirname($abs);
        $parentReal = realpath($parent);
        if ($parentReal === false || !is_dir($parentReal)) {
            throw new AppException('Parent folder not found', httpStatus: 404, publicMessage: 'Target folder not found.');
        }

        $this->assertWithinBase($parentReal);
        $this->assertNoSymlinkPath($parentReal);

        if (!is_writable($parentReal)) {
            throw new AppException('Target folder not writable', httpStatus: 403, publicMessage: 'Target folder is not writable.');
        }

        $name = (string)basename($abs);
        $name = $this->sanitizeBasename($name);
        $this->assertNameLength($name);

        $final = $parentReal . DIRECTORY_SEPARATOR . $name;
        $this->assertWithinBase($final);

        if (in_array(basename($final), $this->protectedBasenames, true)) {
            throw new AppException('Protected target blocked', httpStatus: 403, publicMessage: 'This destination is protected.');
        }

        $this->assertPathLength($final);

        if (file_exists($final)) {
            throw new AppException('Destination exists', httpStatus: 409, publicMessage: 'That name already exists in the destination folder.');
        }

        $collision = $this->findCaseInsensitiveCollision($parentReal, $name);
        if ($collision !== null) {
            throw new AppException('Case-insensitive destination exists', httpStatus: 409, publicMessage: 'That name already exists (case-insensitive conflict).');
        }

        return ['abs' => $final, 'parent' => $parentReal, 'name' => $name];
    }

    private function assertNameLength(string $name): void
    {
        if (strlen($name) > self::NAME_MAX_BYTES) {
            throw new AppException('Name too long', httpStatus: 400, publicMessage: 'Name is too long.');
        }
    }

    private function assertPathLength(string $abs): void
    {
        if (strlen($abs) > self::PATH_MAX_BYTES) {
            throw new AppException('Path too long', httpStatus: 400, publicMessage: 'Path is too long.');
        }
    }

    private function findCaseInsensitiveCollision(string $dirAbs, string $name): ?string
    {
        try {
            $items = scandir($dirAbs);
        } catch (ErrorException) {
            return null;
        }

        if (!is_array($items)) {
            return null;
        }

        $needle = $this->toLower($name);
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            if ($this->toLower((string)$item) === $needle) {
                if ((string)$item !== $name) {
                    return (string)$item;
                }
            }
        }
        return null;
    }

    private function toLower(string $value): string
    {
        if (function_exists('mb_strtolower')) {
            $v = mb_strtolower($value, 'UTF-8');
            if (is_string($v)) {
                return $v;
            }
        }
        return strtolower($value);
    }

    private function allocateTempSiblingPath(string $dirAbs, string $originalName): string
    {
        for ($i = 0; $i < 16; $i++) {
            $tmp = $dirAbs . DIRECTORY_SEPARATOR . '.tmp_' . $originalName . '_' . bin2hex(random_bytes(6));
            if (!file_exists($tmp)) {
                $this->assertWithinBase($tmp);
                return $tmp;
            }
        }

        throw new AppException('Cannot allocate temp path', httpStatus: 500, publicMessage: 'Server is not ready.');
    }

    private function moveByCopyAtomic(string $srcAbs, string $dstAbs): void
    {
        $dstDir = (string)dirname($dstAbs);
        if (!is_dir($dstDir) || !is_writable($dstDir)) {
            throw new AppException('Destination dir not writable', httpStatus: 403, publicMessage: 'Target folder is not writable.');
        }

        $tmp = $this->allocateTempSiblingPath($dstDir, (string)basename($dstAbs));

        if (is_dir($srcAbs)) {
            try {
                $this->copyDirRecursivePreserve($srcAbs, $tmp);
            } catch (Throwable) {
                if (is_dir($tmp)) {
                    try {
                        $this->deleteDirRecursive($tmp);
                    } catch (Throwable) {
                    }
                }
                throw new AppException('Move copy failed', httpStatus: 403, publicMessage: 'Move failed.');
            }
            try {
                if (!rename($tmp, $dstAbs)) {
                     throw new AppException('Finalize move failed', httpStatus: 403, publicMessage: 'Move failed.');
                }
            } catch (ErrorException) {
                $this->deleteDirRecursive($tmp);
                throw new AppException('Finalize move failed', httpStatus: 403, publicMessage: 'Move failed.');
            }

            $this->deleteDirRecursive($srcAbs);
            return;
        }

        if (!is_file($srcAbs)) {
            throw new AppException('Source not file/dir', httpStatus: 400, publicMessage: 'Not found.');
        }

        try {
            $perms = (int)(fileperms($srcAbs) ?: 0640) & 0777;
            $mtime = (int)(filemtime($srcAbs) ?: time());
            if (!copy($srcAbs, $tmp)) {
                throw new AppException('copy for move failed', httpStatus: 403, publicMessage: 'Move failed.');
            }
            chmod($tmp, $perms);
            touch($tmp, $mtime);

            if (!rename($tmp, $dstAbs)) {
                unlink($tmp);
                throw new AppException('Finalize move failed', httpStatus: 403, publicMessage: 'Move failed.');
            }
            if (!unlink($srcAbs)) {
                throw new AppException('Source cleanup failed after move', httpStatus: 500, publicMessage: 'Move completed, but cleanup failed.');
            }
        } catch (ErrorException $e) {
            // cleanup if needed
             if (file_exists($tmp)) {
                try { unlink($tmp); } catch(Throwable) {}
             }
             throw new AppException('Move failed: ' . $e->getMessage(), httpStatus: 403, publicMessage: 'Move failed.');
        }
    }

    private function copyDirRecursivePreserve(string $srcAbs, string $dstAbs): void
    {
        if (file_exists($dstAbs)) {
            throw new AppException('Destination exists', httpStatus: 409, publicMessage: 'Destination already exists.');
        }

        $srcPerms = (int)(fileperms($srcAbs) ?: 0750) & 0777;
        if (!mkdir($dstAbs, $srcPerms, true)) {
            throw new AppException('mkdir for copy failed', httpStatus: 403, publicMessage: 'Copy failed.');
        }
        chmod($dstAbs, $srcPerms);

        $items = scandir($srcAbs);
        if (!is_array($items)) {
            throw new AppException('scandir copy failed', httpStatus: 403, publicMessage: 'Copy failed.');
        }

        foreach ($items as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }

            $from = $srcAbs . DIRECTORY_SEPARATOR . $name;
            $to = $dstAbs . DIRECTORY_SEPARATOR . $name;
            if (is_link($from)) {
                continue;
            }
            if (is_dir($from)) {
                $this->copyDirRecursivePreserve($from, $to);
                continue;
            }
            if (is_file($from)) {
                $perms = (int)(fileperms($from) ?: 0640) & 0777;
                $mtime = (int)(filemtime($from) ?: time());
                if (!copy($from, $to)) {
                    throw new AppException('copy file failed', httpStatus: 403, publicMessage: 'Copy failed.');
                }
                chmod($to, $perms);
                touch($to, $mtime);
            }
        }

        $mtime = (int)(filemtime($srcAbs) ?: time());
        touch($dstAbs, $mtime);
    }

    private function assertWithinBase(string $abs): void
    {
        $base = (string)(realpath($this->allowedRoot) ?: $this->allowedRoot);
        if ($base === '' || !is_dir($base)) {
            throw new AppException('Invalid allowed root', httpStatus: 500, publicMessage: 'Server is not ready.');
        }

        $candidate = rtrim(str_replace('\\', '/', $abs), '/');
        $baseN = rtrim(str_replace('\\', '/', $base), '/');

        if (DIRECTORY_SEPARATOR === '\\') {
            $candidate = strtolower($candidate);
            $baseN = strtolower($baseN);
        }

        if (!str_starts_with($candidate . '/', $baseN . '/')) {
            throw new AppException('Path confinement violation', httpStatus: 403, publicMessage: 'Path is not allowed.');
        }
    }

    private function assertNoSymlinkPath(string $absExisting): void
    {
        $base = (string)(realpath($this->allowedRoot) ?: $this->allowedRoot);
        if ($base === '' || !is_dir($base)) {
            return;
        }

        $baseN = rtrim(str_replace('\\', '/', $base), '/');
        $absN = rtrim(str_replace('\\', '/', $absExisting), '/');

        $cmpBaseN = $baseN;
        $cmpAbsN = $absN;
        if (DIRECTORY_SEPARATOR === '\\') {
            $cmpBaseN = strtolower($cmpBaseN);
            $cmpAbsN = strtolower($cmpAbsN);
        }

        if (!str_starts_with($cmpAbsN . '/', $cmpBaseN . '/')) {
            return;
        }

        $rel = ltrim(substr($absN, strlen($baseN)), '/');
        if ($rel === '') {
            return;
        }

        $parts = array_values(array_filter(explode('/', $rel), static fn (string $p): bool => $p !== ''));
        $cursor = rtrim($base, DIRECTORY_SEPARATOR);
        foreach ($parts as $p) {
            $cursor .= DIRECTORY_SEPARATOR . $p;
            if (file_exists($cursor) && is_link($cursor)) {
                throw new AppException('Symlink segment blocked', httpStatus: 403, publicMessage: 'Path is not allowed.');
            }
        }
    }

    private function normalizeRel(string $rel): string
    {
        if (!is_string($rel)) {
            throw new AppException('Invalid rel type', httpStatus: 400, publicMessage: 'Invalid path.');
        }

        $rel = trim(str_replace('\\', '/', $rel));
        $rel = ltrim($rel, '/');
        if ($rel === '') {
            return '';
        }

        if (str_contains($rel, "\0")) {
            throw new AppException('NUL in path', httpStatus: 400, publicMessage: 'Invalid path.');
        }

        if (preg_match('/[\x00-\x1F\x7F]/', $rel) === 1) {
            throw new AppException('Control chars in path', httpStatus: 400, publicMessage: 'Invalid path.');
        }

        $parts = explode('/', $rel);
        $clean = [];
        foreach ($parts as $p) {
            if ($p === '' || $p === '.') {
                continue;
            }
            if ($p === '..') {
                $last = $clean[count($clean) - 1] ?? null;
                if (is_string($last) && $last !== '..') {
                    array_pop($clean);
                    continue;
                }
                $clean[] = '..';
                continue;
            }
            $clean[] = $p;
        }

        return implode(DIRECTORY_SEPARATOR, $clean);
    }

    private function filesystemRoot(string $baseAbs): string
    {
        $path = str_replace('/', DIRECTORY_SEPARATOR, $baseAbs);

        if (DIRECTORY_SEPARATOR === '\\') {
            if (preg_match('/^\\\\\\\\([^\\\\]+)\\\\([^\\\\]+)/', $path, $m) === 1) {
                return '\\\\' . $m[1] . '\\' . $m[2] . '\\';
            }
            if (preg_match('/^([A-Za-z]):\\\\/', $path, $m) === 1) {
                return strtoupper($m[1]) . ':\\';
            }

            $cursor = rtrim($path, DIRECTORY_SEPARATOR);
            while (true) {
                $parent = dirname($cursor);
                if ($parent === $cursor) {
                    return rtrim($cursor, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
                }
                $cursor = $parent;
            }
        }

        return DIRECTORY_SEPARATOR;
    }

    private function absToRelFromBase(string $abs): string
    {
        $base = $this->baseDirReal;
        $baseInfo = $this->splitAbs($base);
        $absInfo = $this->splitAbs($abs);

        if (($baseInfo['prefix'] ?? '') !== ($absInfo['prefix'] ?? '')) {
            throw new AppException('Path root mismatch', httpStatus: 403, publicMessage: 'Path is not allowed.');
        }

        /** @var array<int, string> $bParts */
        $bParts = $baseInfo['parts'] ?? [];
        /** @var array<int, string> $aParts */
        $aParts = $absInfo['parts'] ?? [];

        $common = 0;
        $max = min(count($bParts), count($aParts));
        for ($i = 0; $i < $max; $i++) {
            $b = $bParts[$i];
            $a = $aParts[$i];
            if (DIRECTORY_SEPARATOR === '\\') {
                if (strcasecmp($b, $a) !== 0) {
                    break;
                }
            } else {
                if ($b !== $a) {
                    break;
                }
            }
            $common++;
        }

        $up = count($bParts) - $common;
        $down = array_slice($aParts, $common);

        $relParts = [];
        for ($i = 0; $i < $up; $i++) {
            $relParts[] = '..';
        }
        foreach ($down as $p) {
            if ($p !== '') {
                $relParts[] = $p;
            }
        }

        return implode('/', $relParts);
    }

    /** @return array{prefix:string,parts:array<int,string>} */
    private function splitAbs(string $abs): array
    {
        $p = str_replace('\\', '/', $abs);
        $p = rtrim($p, '/');

        if (DIRECTORY_SEPARATOR === '\\') {
            if (preg_match('#^//([^/]+)/([^/]+)(/.*)?$#', $p, $m) === 1) {
                $prefix = '//' . strtolower($m[1]) . '/' . strtolower($m[2]);
                $rest = $m[3] ?? '';
                $parts = $rest === '' ? [] : explode('/', trim($rest, '/'));
                return ['prefix' => $prefix, 'parts' => array_values(array_filter($parts, static fn (string $v): bool => $v !== ''))];
            }

            if (preg_match('#^([A-Za-z]):(?:/(.*))?$#', $p, $m) === 1) {
                $prefix = strtolower($m[1]) . ':';
                $rest = $m[2] ?? '';
                $parts = $rest === '' ? [] : explode('/', trim($rest, '/'));
                return ['prefix' => $prefix, 'parts' => array_values(array_filter($parts, static fn (string $v): bool => $v !== ''))];
            }
        }

        $parts = $p === '' ? [] : explode('/', trim($p, '/'));
        return ['prefix' => '', 'parts' => array_values(array_filter($parts, static fn (string $v): bool => $v !== ''))];
    }

    private function sanitizeBasename(string $name): string
    {
        $name = trim($name);
        if ($name === '' || $name === '.' || $name === '..') {
            throw new AppException('Invalid name', httpStatus: 400, publicMessage: 'Invalid name.');
        }
        if (str_contains($name, "\0") || preg_match('/[\\/]/', $name) === 1) {
            throw new AppException('Invalid name chars', httpStatus: 400, publicMessage: 'Invalid name. Do not include slashes.');
        }
        if (preg_match('/[\x00-\x1F\x7F]/', $name) === 1) {
            throw new AppException('Control chars', httpStatus: 400, publicMessage: 'Invalid name. Contains invalid characters.');
        }
        return $name;
    }

    private function sanitizeFilename(string $name): string
    {
        $base = basename(str_replace('\\', '/', $name));
        $base = preg_replace('/[\x00-\x1F\x7F]/', '', $base) ?? $base;
        $base = trim($base);
        $base = preg_replace('/[^A-Za-z0-9._\- ]/u', '_', $base) ?? $base;
        $base = preg_replace('/\s+/', ' ', $base) ?? $base;
        $base = trim($base, ' .');
        if ($base === '' || $base === '.' || $base === '..') {
            return 'upload';
        }
        return $base;
    }

    private function assertUploadAllowed(string $filename): void
    {
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $blocked = [
            'php',
            'phtml',
            'pht',
            'phar',
            'cgi',
            'pl',
            'asp',
            'aspx',
            'jsp',
            'js',
            'htaccess',
            'htpasswd',
            'ini',
            'sh',
        ];
        if ($ext !== '' && in_array($ext, $blocked, true)) {
            throw new AppException('Blocked upload extension', httpStatus: 403, publicMessage: 'That file type is not allowed.');
        }
        if (str_starts_with($filename, '.')) {
            throw new AppException('Dotfile upload blocked', httpStatus: 403, publicMessage: 'That file type is not allowed.');
        }
    }

    private function uniquePath(string $path): string
    {
        if (!file_exists($path)) {
            return $path;
        }

        $dir = dirname($path);
        $name = pathinfo($path, PATHINFO_FILENAME);
        $ext = pathinfo($path, PATHINFO_EXTENSION);

        for ($i = 1; $i <= 999; $i++) {
            $candidate = $dir . DIRECTORY_SEPARATOR . $name . '-' . $i . ($ext !== '' ? ('.' . $ext) : '');
            if (!file_exists($candidate)) {
                return $candidate;
            }
        }

        throw new AppException('Cannot allocate unique filename', httpStatus: 409, publicMessage: 'Please rename the file and try again.');
    }

    private function copyDirRecursive(string $srcAbs, string $dstAbs): void
    {
        if (file_exists($dstAbs)) {
            throw new AppException('Destination exists', httpStatus: 409, publicMessage: 'Destination already exists.');
        }
        try {
            if (!mkdir($dstAbs, 0750, true)) {
                throw new AppException('mkdir for copy failed', httpStatus: 403, publicMessage: 'Copy failed.');
            }
        } catch (ErrorException $e) {
             throw new AppException('mkdir for copy failed: ' . $e->getMessage(), httpStatus: 403, publicMessage: 'Copy failed.');
        }

        $items = scandir($srcAbs);
        if (!is_array($items)) {
            throw new AppException('scandir copy failed', httpStatus: 403, publicMessage: 'Copy failed.');
        }

        foreach ($items as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }

            $from = $srcAbs . DIRECTORY_SEPARATOR . $name;
            $to = $dstAbs . DIRECTORY_SEPARATOR . $name;
            if (is_link($from)) {
                continue;
            }
            if (is_dir($from)) {
                $this->copyDirRecursive($from, $to);
                continue;
            }
            if (is_file($from)) {
                try {
                    if (!copy($from, $to)) {
                        throw new AppException('copy file failed', httpStatus: 403, publicMessage: 'Copy failed.');
                    }
                    chmod($to, 0640);
                } catch (ErrorException $e) {
                     throw new AppException('copy file failed: ' . $e->getMessage(), httpStatus: 403, publicMessage: 'Copy failed.');
                }
            }
        }
    }

    private function deleteDirRecursive(string $dirAbs): void
    {
        try {
            $items = scandir($dirAbs);
        } catch (ErrorException $e) {
             throw new AppException('scandir delete failed: ' . $e->getMessage(), httpStatus: 403, publicMessage: 'Delete failed.');
        }

        if (!is_array($items)) {
            throw new AppException('scandir delete failed', httpStatus: 403, publicMessage: 'Delete failed.');
        }

        foreach ($items as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }

            $child = $dirAbs . DIRECTORY_SEPARATOR . $name;
            if (is_link($child)) {
                continue;
            }
            if (is_dir($child)) {
                $this->deleteDirRecursive($child);
                continue;
            }
            if (is_file($child)) {
                try {
                    if (!unlink($child)) {
                        throw new AppException('unlink failed', httpStatus: 403, publicMessage: 'Delete failed.');
                    }
                } catch (ErrorException) {
                     throw new AppException('unlink failed', httpStatus: 403, publicMessage: 'Delete failed.');
                }
            }
        }

        try {
            if (!rmdir($dirAbs)) {
                throw new AppException('rmdir failed', httpStatus: 403, publicMessage: 'Delete failed.');
            }
        } catch (ErrorException) {
             throw new AppException('rmdir failed', httpStatus: 403, publicMessage: 'Delete failed.');
        }
    }

    private function chmodDirRecursive(string $dirAbs, int $mode): void
    {
        try {
            if (!chmod($dirAbs, $mode)) {
                throw new AppException('chmod dir failed', httpStatus: 403, publicMessage: 'Permission change failed.');
            }
        } catch (ErrorException) {
             throw new AppException('chmod dir failed', httpStatus: 403, publicMessage: 'Permission change failed.');
        }

        try {
            $items = scandir($dirAbs);
        } catch (ErrorException) {
            return;
        }

        if (!is_array($items)) {
            return;
        }

        foreach ($items as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }

            $child = $dirAbs . DIRECTORY_SEPARATOR . $name;
            if (is_link($child)) {
                continue;
            }
            if (is_dir($child)) {
                $this->chmodDirRecursive($child, $mode);
                continue;
            }
            if (is_file($child)) {
                try {
                    chmod($child, $mode);
                } catch (ErrorException) {}
            }
        }
    }

    private function isPathWithin(string $candidateAbs, string $parentAbs): bool
    {
        $c = str_replace('\\', '/', $candidateAbs);
        $p = rtrim(str_replace('\\', '/', $parentAbs), '/');
        return str_starts_with($c . '/', $p . '/');
    }

    /** @return array{progress_id:string,zip:string,entries:int,bytes:int,skipped_symlinks:int} */
    public function zipCreate(string $srcRel, string $dstRel, string $level, ?string $progressId = null): array
    {
        if (!class_exists(ZipArchive::class)) {
            throw new ZipOpException('ZipArchive missing', 500, 'ZIP support is not available on this server.', ZipErrorCode::UNAVAILABLE);
        }

        $startedAt = microtime(true);
        $srcAbs = $this->resolveExistingPath($srcRel);
        $isDir = is_dir($srcAbs);
        $isFile = is_file($srcAbs);
        if (!$isDir && !$isFile) {
            throw new ZipOpException('Source not file/dir', 400, 'Not found.', ZipErrorCode::IO);
        }

        $progressId = $this->zipNormalizeProgressId($progressId);
        $progressPath = $this->zipProgressPath($progressId);
        $this->zipWriteProgress($progressPath, [
            'state' => 'running',
            'op' => 'create',
            'processed' => 0,
            'total' => 0,
            'bytes' => 0,
            'message' => 'Starting…',
            'updated_at' => time(),
        ]);

        $levelFlag = match (strtolower(trim($level))) {
            'fast' => 1,
            'maximum', 'max' => 9,
            default => 6,
        };

        $srcRelNorm = $this->normalizeRel($srcRel);
        $zipRoot = $this->relToZipPath($srcRelNorm);

        if (trim($dstRel) === '') {
            $srcDirRel = $this->absToRelFromBase(dirname($srcAbs));
            $zipName = basename($srcAbs) . '.zip';
            $dstRel = ($srcDirRel !== '' ? ($srcDirRel . '/' . $zipName) : $zipName);
        }

        $dstRelNorm = $this->normalizeRel($dstRel);
        if (!str_ends_with(strtolower($dstRelNorm), '.zip')) {
            $dstRelNorm .= '.zip';
        }

        $dstInfo = $this->resolveTargetForWrite($dstRelNorm);
        $dstAbs = $dstInfo['abs'];

        $lockHandles = $this->zipAcquireLocks([$dstAbs], waitMs: 8000);
        try {
            $total = 0;
            $bytesTotal = 0;
            $skippedLinks = 0;

            if ($isFile) {
                $total = 1;
                try {
                    $bytesTotal = (int)filesize($srcAbs);
                } catch (Throwable) {
                    $bytesTotal = 0;
                }
            } else {
                $total = 1;
                $it = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($srcAbs, FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO),
                    RecursiveIteratorIterator::SELF_FIRST,
                );
                foreach ($it as $info) {
                    $this->zipExtendTimeLimit();
                    $this->zipCheckTimeout($startedAt);
                    if (!$info instanceof SplFileInfo) {
                        continue;
                    }
                    if ($info->isLink()) {
                        $skippedLinks++;
                        continue;
                    }
                    if ($info->isDir()) {
                        $total++;
                        continue;
                    }
                    if ($info->isFile()) {
                        $total++;
                        $bytesTotal += (int)$info->getSize();
                        continue;
                    }
                }
            }

            $this->zipWriteProgress($progressPath, [
                'state' => 'running',
                'op' => 'create',
                'processed' => 0,
                'total' => $total,
                'bytes' => 0,
                'message' => 'Preparing…',
                'updated_at' => time(),
            ]);

            $zip = new ZipArchive();
            $openResult = $zip->open($dstAbs, ZipArchive::CREATE | ZipArchive::EXCL);
            if ($openResult !== true) {
                $detail = $this->zipOpenErrorDetail($openResult);
                throw new ZipOpException('Zip open failed: ' . (string)$openResult, 500, 'Cannot create ZIP archive.', ZipErrorCode::OPEN_FAILED, $detail);
            }

            $processed = 0;
            $bytesProcessed = 0;
            try {
                if ($isFile) {
                    $this->zipExtendTimeLimit();
                    $this->zipCheckTimeout($startedAt);
                    if (!$zip->addFile($srcAbs, $zipRoot)) {
                        throw new ZipOpException('addFile failed', 500, 'Failed to add file to ZIP.', ZipErrorCode::IO);
                    }
                    if (method_exists($zip, 'setCompressionName')) {
                        $zip->setCompressionName($zipRoot, ZipArchive::CM_DEFLATE, $levelFlag);
                    }
                    $processed = 1;
                    $bytesProcessed = $bytesTotal;
                    $this->zipWriteProgress($progressPath, [
                        'state' => 'running',
                        'op' => 'create',
                        'processed' => $processed,
                        'total' => $total,
                        'bytes' => $bytesProcessed,
                        'message' => 'Adding file…',
                        'updated_at' => time(),
                    ]);
                } else {
                    $zip->addEmptyDir($zipRoot . '/');
                    $processed++;

                    $it = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator($srcAbs, FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO),
                        RecursiveIteratorIterator::SELF_FIRST,
                    );

                    $tick = 0;
                    foreach ($it as $info) {
                        $this->zipExtendTimeLimit();
                        $this->zipCheckTimeout($startedAt);
                        if (!$info instanceof SplFileInfo) {
                            continue;
                        }
                        if ($info->isLink()) {
                            $skippedLinks++;
                            continue;
                        }

                        $path = $info->getPathname();
                        if (!is_string($path) || $path === '') {
                            continue;
                        }

                        $relWithin = substr($path, strlen($srcAbs));
                        $relWithin = ltrim(str_replace('\\', '/', $relWithin), '/');
                        $local = $zipRoot . ($relWithin !== '' ? ('/' . $relWithin) : '');

                        if ($info->isDir()) {
                            $zip->addEmptyDir(rtrim($local, '/') . '/');
                            $processed++;
                        } elseif ($info->isFile()) {
                            if (!$zip->addFile($path, $local)) {
                                throw new ZipOpException('addFile failed', 500, 'Failed to add file to ZIP.', ZipErrorCode::IO, $local);
                            }
                            if (method_exists($zip, 'setCompressionName')) {
                                $zip->setCompressionName($local, ZipArchive::CM_DEFLATE, $levelFlag);
                            }
                            $processed++;
                            $bytesProcessed += (int)$info->getSize();
                        } else {
                            continue;
                        }

                        $tick++;
                        if ($tick % 50 === 0) {
                            $this->zipWriteProgress($progressPath, [
                                'state' => 'running',
                                'op' => 'create',
                                'processed' => $processed,
                                'total' => $total,
                                'bytes' => $bytesProcessed,
                                'message' => 'Compressing…',
                                'updated_at' => time(),
                            ]);
                        }
                    }

                    $this->zipWriteProgress($progressPath, [
                        'state' => 'running',
                        'op' => 'create',
                        'processed' => $processed,
                        'total' => $total,
                        'bytes' => $bytesProcessed,
                        'message' => 'Finalizing…',
                        'updated_at' => time(),
                    ]);
                }
            } finally {
                $zip->close();
            }

            $zipRel = $this->absToRelFromBase($dstAbs);
            $this->zipWriteProgress($progressPath, [
                'state' => 'done',
                'op' => 'create',
                'processed' => $total,
                'total' => $total,
                'bytes' => $bytesTotal,
                'message' => 'Done.',
                'result' => ['zip' => $zipRel],
                'updated_at' => time(),
            ]);

            return [
                'progress_id' => $progressId,
                'zip' => $zipRel,
                'entries' => $total,
                'bytes' => $bytesTotal,
                'skipped_symlinks' => $skippedLinks,
            ];
        } catch (ZipOpException $e) {
            $this->zipWriteProgress($progressPath, [
                'state' => 'error',
                'op' => 'create',
                'message' => $e->publicMessage ?? 'ZIP operation failed.',
                'error_code' => $e->errorCode,
                'detail' => $e->detail,
                'updated_at' => time(),
            ]);
            @unlink($dstAbs);
            throw $e;
        } catch (Throwable $e) {
            $this->zipWriteProgress($progressPath, [
                'state' => 'error',
                'op' => 'create',
                'message' => 'ZIP operation failed.',
                'updated_at' => time(),
            ]);
            @unlink($dstAbs);
            throw $e;
        } finally {
            $this->zipReleaseLocks($lockHandles);
        }
    }

    /** @return array{progress_id:string,extracted_to:string,files:int,dirs:int,nested_zips:int} */
    public function zipExtract(string $zipRel, string $destDirRel, string $password, bool $recursive, ?string $progressId = null): array
    {
        if (!class_exists(ZipArchive::class)) {
            throw new ZipOpException('ZipArchive missing', 500, 'ZIP support is not available on this server.', ZipErrorCode::UNAVAILABLE);
        }

        $startedAt = microtime(true);
        $zipAbs = $this->resolveExistingPath($zipRel);
        if (!is_file($zipAbs)) {
            throw new ZipOpException('Not a file', 400, 'Not a file.', ZipErrorCode::IO);
        }

        if (!is_readable($zipAbs)) {
            throw new ZipOpException('ZIP not readable', 403, 'ZIP file is not readable.', ZipErrorCode::IO);
        }

        $zipExt = strtolower(pathinfo($zipAbs, PATHINFO_EXTENSION));
        if ($zipExt !== 'zip') {
            throw new ZipOpException('Not a zip', 400, 'Only .zip files can be extracted.', ZipErrorCode::INVALID_ZIP);
        }

        $destAbs = null;
        if (trim($destDirRel) === '') {
            $destAbs = realpath(dirname($zipAbs));
            if ($destAbs === false || !is_dir($destAbs)) {
                throw new ZipOpException('ZIP parent missing', 500, 'Destination folder is not available.', ZipErrorCode::IO);
            }
            $this->assertWithinBase($destAbs);
            $this->assertNoSymlinkPath($destAbs);
        } else {
            $destAbs = $this->resolveExistingDir($destDirRel);
        }

        if (!is_writable($destAbs)) {
            throw new ZipOpException('Destination not writable', 403, 'Destination folder is not writable.', ZipErrorCode::DEST_NOT_WRITABLE);
        }

        $progressId = $this->zipNormalizeProgressId($progressId);
        $progressPath = $this->zipProgressPath($progressId);
        $this->zipWriteProgress($progressPath, [
            'state' => 'running',
            'op' => 'extract',
            'processed' => 0,
            'total' => 0,
            'bytes' => 0,
            'message' => 'Starting…',
            'updated_at' => time(),
        ]);

        $lockHandles = $this->zipAcquireLocks([$zipAbs, $destAbs], waitMs: 12000);
        try {
            $zip = new ZipArchive();
            $openResult = $zip->open($zipAbs);
            if ($openResult !== true) {
                $detail = $this->zipOpenErrorDetail($openResult);
                throw new ZipOpException('Zip open failed: ' . (string)$openResult, 400, 'Cannot open ZIP file.', ZipErrorCode::OPEN_FAILED, $detail);
            }

            if ($password !== '') {
                $zip->setPassword($password);
            }

            $numFiles = $zip->numFiles;
            if (!is_int($numFiles) || $numFiles < 0) {
                $zip->close();
                throw new ZipOpException('Invalid numFiles', 400, 'Invalid ZIP file.', ZipErrorCode::INVALID_ZIP);
            }

            $entryMap = [];
            for ($i = 0; $i < $numFiles; $i++) {
                $this->zipExtendTimeLimit();
                $this->zipCheckTimeout($startedAt);
                $stat = $zip->statIndex($i, ZipArchive::FL_UNCHANGED);
                if (!is_array($stat)) {
                    $zip->close();
                    throw new ZipOpException('statIndex failed', 400, 'Corrupted or incomplete ZIP file.', ZipErrorCode::CORRUPT);
                }
                $name = $stat['name'] ?? null;
                if (!is_string($name) || $name === '') {
                    $zip->close();
                    throw new ZipOpException('Invalid entry name', 400, 'Invalid ZIP file.', ZipErrorCode::INVALID_ZIP);
                }
                $norm = $this->zipNormalizeEntryName($name);
                $entryMap[] = ['zip_name' => $name, 'path' => $norm['path'], 'is_dir' => $norm['is_dir'], 'mtime' => (int)($stat['mtime'] ?? 0)];
            }

            $this->zipWriteProgress($progressPath, [
                'state' => 'running',
                'op' => 'extract',
                'processed' => 0,
                'total' => $numFiles,
                'bytes' => 0,
                'message' => 'Validating…',
                'updated_at' => time(),
            ]);

            $files = 0;
            $dirs = 0;
            $nested = 0;
            $bytes = 0;
            $zipCandidates = [];

            try {
                $tick = 0;
                foreach ($entryMap as $idx => $entry) {
                    $this->zipExtendTimeLimit();
                    $this->zipCheckTimeout($startedAt);
                    $zipName = $entry['zip_name'];
                    $relPath = $entry['path'];
                    $isDir = $entry['is_dir'];
                    $mtime = (int)($entry['mtime'] ?? 0);
                    $targetAbs = $destAbs . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relPath);
                    $this->assertWithinBase($targetAbs);

                    $perms = $this->zipEntryPerms($zip, $idx, $isDir);

                    if ($isDir) {
                        if (!is_dir($targetAbs)) {
                            try {
                                if (!mkdir($targetAbs, $perms ?? 0750, true)) {
                                    throw new ZipOpException('mkdir failed', 403, 'Cannot create destination folder.', ZipErrorCode::IO, $relPath);
                                }
                            } catch (ErrorException $e) {
                                throw new ZipOpException('mkdir failed: ' . $e->getMessage(), 403, 'Cannot create destination folder.', ZipErrorCode::IO, $relPath);
                            }
                        }
                        if ($perms !== null) {
                            try {
                                chmod($targetAbs, $perms);
                            } catch (Throwable) {
                            }
                        }
                        if ($mtime > 0) {
                            try {
                                touch($targetAbs, $mtime);
                            } catch (Throwable) {
                            }
                        }
                        $dirs++;
                    } else {
                        $parent = dirname($targetAbs);
                        if (!is_dir($parent)) {
                            try {
                                if (!mkdir($parent, 0750, true)) {
                                    throw new ZipOpException('mkdir parent failed', 403, 'Cannot create destination folder.', ZipErrorCode::IO, $relPath);
                                }
                            } catch (ErrorException $e) {
                                throw new ZipOpException('mkdir parent failed: ' . $e->getMessage(), 403, 'Cannot create destination folder.', ZipErrorCode::IO, $relPath);
                            }
                        }

                        if (file_exists($targetAbs)) {
                            throw new ZipOpException('Destination exists', 409, 'Destination already exists. Extract to an empty folder.', ZipErrorCode::DEST_EXISTS, $relPath);
                        }

                        $in = $zip->getStream($zipName);
                        if ($in === false) {
                            $detail = method_exists($zip, 'getStatusString') ? (string)$zip->getStatusString() : null;
                            if ($password === '') {
                                throw new ZipOpException('Entry stream failed', 400, 'ZIP is password-protected. Provide a password.', ZipErrorCode::PASSWORD_REQUIRED, $detail);
                            }
                            throw new ZipOpException('Entry stream failed', 400, 'Wrong ZIP password or corrupted ZIP.', ZipErrorCode::WRONG_PASSWORD, $detail);
                        }

                        $out = null;
                        try {
                            $out = fopen($targetAbs, 'xb');
                            if ($out === false) {
                                throw new ZipOpException('fopen failed', 403, 'Cannot write extracted file.', ZipErrorCode::IO, $relPath);
                            }
                            $bytes += $this->zipStreamCopy($in, $out, $startedAt);
                        } finally {
                            if (is_resource($in)) {
                                fclose($in);
                            }
                            if (is_resource($out)) {
                                fclose($out);
                            }
                        }

                        if ($perms !== null) {
                            try {
                                chmod($targetAbs, $perms);
                            } catch (Throwable) {
                            }
                        }
                        if ($mtime > 0) {
                            try {
                                touch($targetAbs, $mtime);
                            } catch (Throwable) {
                            }
                        }

                        $files++;
                        if ($recursive && str_ends_with(strtolower($relPath), '.zip')) {
                            $zipCandidates[] = $targetAbs;
                        }
                    }

                    $tick++;
                    if ($tick % 20 === 0) {
                        $this->zipWriteProgress($progressPath, [
                            'state' => 'running',
                            'op' => 'extract',
                            'processed' => $tick,
                            'total' => $numFiles,
                            'bytes' => $bytes,
                            'message' => 'Extracting…',
                            'updated_at' => time(),
                        ]);
                    }
                }
            } finally {
                $zip->close();
            }

            if ($recursive && count($zipCandidates) > 0) {
                $nested = $this->zipExtractNested($zipCandidates, $destAbs, $password, $progressPath, $startedAt);
            }

            $destRelOut = $this->absToRelFromBase($destAbs);
            $this->zipWriteProgress($progressPath, [
                'state' => 'done',
                'op' => 'extract',
                'processed' => $numFiles,
                'total' => $numFiles,
                'bytes' => $bytes,
                'message' => 'Done.',
                'result' => ['extracted_to' => $destRelOut, 'files' => $files, 'dirs' => $dirs, 'nested_zips' => $nested],
                'updated_at' => time(),
            ]);

            return [
                'progress_id' => $progressId,
                'extracted_to' => $destRelOut,
                'files' => $files,
                'dirs' => $dirs,
                'nested_zips' => $nested,
            ];
        } catch (ZipOpException $e) {
            $this->zipWriteProgress($progressPath, [
                'state' => 'error',
                'op' => 'extract',
                'message' => $e->publicMessage ?? 'ZIP operation failed.',
                'error_code' => $e->errorCode,
                'detail' => $e->detail,
                'updated_at' => time(),
            ]);
            throw $e;
        } catch (Throwable $e) {
            $this->zipWriteProgress($progressPath, [
                'state' => 'error',
                'op' => 'extract',
                'message' => 'ZIP operation failed.',
                'updated_at' => time(),
            ]);
            throw $e;
        } finally {
            $this->zipReleaseLocks($lockHandles);
        }
    }

    /** @return array{state:string,op?:string,processed?:int,total?:int,bytes?:int,message?:string,result?:mixed,updated_at?:int} */
    public function zipProgress(string $progressId): array
    {
        $progressId = $this->zipNormalizeProgressId($progressId);
        $path = $this->zipProgressPath($progressId);
        if (!file_exists($path)) {
            return ['state' => 'missing'];
        }

        $fp = fopen($path, 'rb');
        if ($fp === false) {
            return ['state' => 'missing'];
        }
        try {
            if (!flock($fp, LOCK_SH)) {
                return ['state' => 'missing'];
            }
            $raw = stream_get_contents($fp);
            if (!is_string($raw) || $raw === '') {
                return ['state' => 'missing'];
            }
            $json = json_decode($raw, true);
            if (!is_array($json)) {
                return ['state' => 'missing'];
            }
            if (!isset($json['state']) || !is_string($json['state'])) {
                $json['state'] = 'missing';
            }
            return $json;
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    private function zipNormalizeProgressId(?string $progressId): string
    {
        $id = is_string($progressId) ? trim($progressId) : '';
        if ($id === '') {
            $id = bin2hex(random_bytes(12));
        }
        $id = preg_replace('/[^A-Za-z0-9_\-]/', '', $id) ?? $id;
        if ($id === '') {
            $id = bin2hex(random_bytes(12));
        }
        return substr($id, 0, 64);
    }

    private function zipProgressPath(string $progressId): string
    {
        $sid = session_id();
        if ($sid === '') {
            $sid = 'nosess';
        }
        return rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'tfm_zip_progress_' . $sid . '_' . $progressId . '.json';
    }

    /** @param array<string,mixed> $data */
    private function zipWriteProgress(string $path, array $data): void
    {
        $fp = fopen($path, 'c+');
        if ($fp === false) {
            return;
        }
        try {
            if (!flock($fp, LOCK_EX)) {
                return;
            }
            $payload = json_encode($data, flags: JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if (!is_string($payload)) {
                return;
            }
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, $payload);
            fflush($fp);
        } catch (Throwable) {
        } finally {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    /** @param array<int,string> $absPaths @return array<int, resource> */
    private function zipAcquireLocks(array $absPaths, int $waitMs): array
    {
        $lockPaths = [];
        foreach ($absPaths as $p) {
            $p = trim($p);
            if ($p === '') {
                continue;
            }
            $dir = is_dir($p) ? $p : dirname($p);
            $lock = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.tfm_zip_lock_' . sha1($p) . '.lock';
            $this->assertWithinBase($lock);
            $lockPaths[] = $lock;
        }
        sort($lockPaths, SORT_STRING);

        $handles = [];
        $start = (int)floor(microtime(true) * 1000);
        foreach ($lockPaths as $lp) {
            $fp = fopen($lp, 'c+');
            if ($fp === false) {
                $this->zipReleaseLocks($handles);
                throw new ZipOpException('Lock open failed', 500, 'Server cannot lock ZIP operation.', ZipErrorCode::IO);
            }
            $locked = false;
            while (true) {
                if (flock($fp, LOCK_EX | LOCK_NB)) {
                    $locked = true;
                    break;
                }
                $now = (int)floor(microtime(true) * 1000);
                if (($now - $start) > $waitMs) {
                    fclose($fp);
                    $this->zipReleaseLocks($handles);
                    throw new ZipOpException('Lock timeout', 423, 'ZIP file is busy. Try again.', ZipErrorCode::LOCK_TIMEOUT);
                }
                usleep(100000);
            }
            if ($locked) {
                $handles[] = $fp;
            } else {
                fclose($fp);
            }
        }
        return $handles;
    }

    /** @param array<int, resource> $handles */
    private function zipReleaseLocks(array $handles): void
    {
        foreach ($handles as $h) {
            if (is_resource($h)) {
                try {
                    flock($h, LOCK_UN);
                } catch (Throwable) {
                }
                try {
                    fclose($h);
                } catch (Throwable) {
                }
            }
        }
    }

    private function zipExtendTimeLimit(): void
    {
        try {
            set_time_limit(30);
        } catch (Throwable) {
        }
    }

    private function zipCheckTimeout(float $startedAt): void
    {
        if ((microtime(true) - $startedAt) > self::ZIP_MAX_SECONDS) {
            throw new ZipOpException('ZIP timeout', 408, 'ZIP operation timed out.', ZipErrorCode::TIMEOUT);
        }
    }

    private function relToZipPath(string $rel): string
    {
        $p = str_replace('\\', '/', $rel);
        $p = trim($p, '/');
        return $p === '' ? '' : $p;
    }

    /** @return array{path:string,is_dir:bool} */
    private function zipNormalizeEntryName(string $name): array
    {
        $n = str_replace('\\', '/', $name);
        $n = ltrim($n, '/');
        if ($n === '' || str_contains($n, "\0") || preg_match('/[\x00-\x1F\x7F]/', $n) === 1) {
            throw new ZipOpException('Invalid entry name', 400, 'Invalid ZIP file entry name.', ZipErrorCode::INVALID_ZIP);
        }
        if (preg_match('/^[A-Za-z]:\//', $n) === 1 || str_starts_with($n, '//')) {
            throw new ZipOpException('Absolute entry blocked', 400, 'ZIP contains unsafe paths.', ZipErrorCode::TRAVERSAL, $n);
        }

        $isDir = str_ends_with($n, '/');
        $n = rtrim($n, '/');
        $parts = array_values(array_filter(explode('/', $n), static fn (string $p): bool => $p !== '' && $p !== '.'));
        foreach ($parts as $p) {
            if ($p === '..') {
                throw new ZipOpException('Traversal blocked', 400, 'ZIP contains unsafe paths.', ZipErrorCode::TRAVERSAL, $name);
            }
        }
        $safe = implode('/', $parts);
        if ($safe === '') {
            $safe = '_';
        }
        return ['path' => $safe . ($isDir ? '/' : ''), 'is_dir' => $isDir];
    }

    private function zipOpenErrorDetail(int|bool $openResult): ?string
    {
        $code = is_int($openResult) ? $openResult : null;
        if ($code === null) {
            return null;
        }
        $map = [
            ZipArchive::ER_EXISTS => 'File already exists.',
            ZipArchive::ER_INCONS => 'Zip archive inconsistent.',
            ZipArchive::ER_INVAL => 'Invalid argument.',
            ZipArchive::ER_MEMORY => 'Malloc failure.',
            ZipArchive::ER_NOENT => 'No such file.',
            ZipArchive::ER_NOZIP => 'Not a zip archive.',
            ZipArchive::ER_OPEN => 'Cannot open file.',
            ZipArchive::ER_READ => 'Read error.',
            ZipArchive::ER_SEEK => 'Seek error.',
        ];
        return $map[$code] ?? ('Zip error: ' . $code);
    }

    private function zipEntryPerms(ZipArchive $zip, int $index, bool $isDir): ?int
    {
        if (!method_exists($zip, 'getExternalAttributesIndex')) {
            return $isDir ? 0750 : 0640;
        }
        $opsys = 0;
        $attr = 0;
        $ok = $zip->getExternalAttributesIndex($index, $opsys, $attr);
        if ($ok !== true) {
            return $isDir ? 0750 : 0640;
        }
        $mode = ($attr >> 16) & 0xFFFF;
        $perms = $mode & 0777;
        if ($perms <= 0) {
            return $isDir ? 0750 : 0640;
        }
        return $perms;
    }

    private function zipStreamCopy(mixed $in, mixed $out, float $startedAt): int
    {
        $total = 0;
        $chunk = 1024 * 1024;
        while (!feof($in)) {
            $this->zipExtendTimeLimit();
            $this->zipCheckTimeout($startedAt);
            $buf = fread($in, $chunk);
            if ($buf === false) {
                throw new ZipOpException('Read from zip failed', 400, 'Corrupted or incomplete ZIP file.', ZipErrorCode::CORRUPT);
            }
            if ($buf === '') {
                break;
            }
            $len = strlen($buf);
            $written = 0;
            while ($written < $len) {
                $n = fwrite($out, substr($buf, $written));
                if ($n === false || $n === 0) {
                    throw new ZipOpException('Write failed', 403, 'Cannot write extracted file.', ZipErrorCode::IO);
                }
                $written += $n;
            }
            $total += $len;
            if ($total > (3 * 1024 * 1024 * 1024)) {
                throw new ZipOpException('Zip entry too large', 400, 'ZIP entry is too large.', ZipErrorCode::TOO_LARGE);
            }
        }
        return $total;
    }

    /** @param array<int,string> $zipAbsList */
    private function zipExtractNested(array $zipAbsList, string $destRootAbs, string $password, string $progressPath, float $startedAt): int
    {
        $queue = [];
        $seen = [];
        foreach ($zipAbsList as $p) {
            $rp = realpath($p);
            if ($rp === false) {
                continue;
            }
            $seen[$rp] = true;
            $queue[] = ['zip' => $rp, 'depth' => 1];
        }

        $count = 0;
        while (count($queue) > 0) {
            $item = array_shift($queue);
            if (!is_array($item)) {
                break;
            }
            $zipAbs = (string)($item['zip'] ?? '');
            $depth = (int)($item['depth'] ?? 1);
            if ($zipAbs === '' || $depth > 5) {
                continue;
            }
            if ($count >= 25) {
                break;
            }
            if (!is_file($zipAbs) || !is_readable($zipAbs)) {
                continue;
            }
            $this->zipExtendTimeLimit();
            $this->zipCheckTimeout($startedAt);
            $this->assertWithinBase($zipAbs);
            $dirAbs = realpath(dirname($zipAbs));
            if ($dirAbs === false || !is_dir($dirAbs) || !is_writable($dirAbs)) {
                continue;
            }
            $this->assertWithinBase($dirAbs);
            if (!$this->isPathWithin($dirAbs, $destRootAbs)) {
                continue;
            }

            $base = pathinfo($zipAbs, PATHINFO_FILENAME);
            $base = $base !== '' ? $base : 'nested';
            $dest = rtrim($dirAbs, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $base;
            $suffix = 0;
            while (file_exists($dest) && $suffix < 100) {
                $suffix++;
                $dest = rtrim($dirAbs, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $base . '-' . $suffix;
            }
            if (file_exists($dest)) {
                continue;
            }

            try {
                if (!mkdir($dest, 0750, true)) {
                    continue;
                }
            } catch (Throwable) {
                continue;
            }

            $lockHandles = $this->zipAcquireLocks([$zipAbs, $dest], waitMs: 12000);
            try {
                $zip = new ZipArchive();
                $openResult = $zip->open($zipAbs);
                if ($openResult !== true) {
                    $zip->close();
                    continue;
                }
                if ($password !== '') {
                    $zip->setPassword($password);
                }
                $numFiles = $zip->numFiles;
                if (!is_int($numFiles) || $numFiles < 0) {
                    $zip->close();
                    continue;
                }

                $this->zipWriteProgress($progressPath, [
                    'state' => 'running',
                    'op' => 'extract',
                    'processed' => $numFiles,
                    'total' => $numFiles,
                    'bytes' => 0,
                    'message' => 'Extracting nested ZIP…',
                    'updated_at' => time(),
                ]);

                $localCandidates = [];
                for ($i = 0; $i < $numFiles; $i++) {
                    $this->zipExtendTimeLimit();
                    $this->zipCheckTimeout($startedAt);
                    $stat = $zip->statIndex($i, ZipArchive::FL_UNCHANGED);
                    if (!is_array($stat)) {
                        $zip->close();
                        continue 2;
                    }
                    $name = $stat['name'] ?? null;
                    if (!is_string($name) || $name === '') {
                        $zip->close();
                        continue 2;
                    }
                    $norm = $this->zipNormalizeEntryName($name);
                    $relPath = $norm['path'];
                    $isDir = $norm['is_dir'];
                    $mtime = (int)($stat['mtime'] ?? 0);
                    $targetAbs = $dest . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relPath);
                    $this->assertWithinBase($targetAbs);

                    $perms = $this->zipEntryPerms($zip, $i, $isDir);
                    if ($isDir) {
                        if (!is_dir($targetAbs)) {
                            @mkdir($targetAbs, $perms ?? 0750, true);
                        }
                        if ($mtime > 0) {
                            @touch($targetAbs, $mtime);
                        }
                        continue;
                    }

                    $parent = dirname($targetAbs);
                    if (!is_dir($parent)) {
                        @mkdir($parent, 0750, true);
                    }
                    if (file_exists($targetAbs)) {
                        continue;
                    }
                    $in = $zip->getStream($name);
                    if ($in === false) {
                        if ($password === '') {
                            $zip->close();
                            continue 2;
                        }
                        $zip->close();
                        continue 2;
                    }
                    $out = null;
                    try {
                        $out = fopen($targetAbs, 'xb');
                        if ($out === false) {
                            continue;
                        }
                        $this->zipStreamCopy($in, $out, $startedAt);
                    } finally {
                        if (is_resource($in)) {
                            fclose($in);
                        }
                        if (is_resource($out)) {
                            fclose($out);
                        }
                    }
                    if ($perms !== null) {
                        @chmod($targetAbs, $perms);
                    }
                    if ($mtime > 0) {
                        @touch($targetAbs, $mtime);
                    }
                    if (str_ends_with(strtolower($relPath), '.zip')) {
                        $localCandidates[] = $targetAbs;
                    }
                }
                $zip->close();

                foreach ($localCandidates as $c) {
                    $rp = realpath($c);
                    if ($rp === false) {
                        continue;
                    }
                    if (isset($seen[$rp])) {
                        continue;
                    }
                    $seen[$rp] = true;
                    $queue[] = ['zip' => $rp, 'depth' => $depth + 1];
                }
            } catch (Throwable) {
            } finally {
                $this->zipReleaseLocks($lockHandles);
            }

            $count++;
        }

        return $count;
    }
}

final class Actions
{
    public function __construct(
        private readonly Security $security,
        private readonly FsService $fs,
    ) {
    }

    /** @return array{ok:bool,data?:mixed,error?:string,meta?:mixed} */
    public function login(): array
    {
        $password = $this->readPostString('password', maxLen: 256, allowEmpty: true, trim: true);

        if ($password === '') {
            throw new AppException('Empty password', httpStatus: 400, publicMessage: 'Password is required.');
        }
        $csrf = $this->readPostString('csrf', maxLen: 128);
        $this->security->attemptLogin($password, $csrf);
        return ['ok' => true, 'data' => ['csrf' => $this->security->csrfToken()]];
    }

    #[RequiresAuth]
    #[RequiresCsrf]
    public function logout(): array
    {
        $this->security->logout();
        return ['ok' => true, 'data' => ['logged_out' => true]];
    }

    #[RequiresAuth]
    public function list(): array
    {
        $dirRaw = $this->readQueryString('dir', maxLen: 2048, allowEmpty: true);
        return [
            'ok' => true,
            'data' => [
                'dir' => $this->fs->canonicalDir($dirRaw),
                'entries' => $this->fs->listDir($dirRaw),
            ],
        ];
    }

    #[RequiresAuth]
    public function download(): never
    {
        $path = $this->readQueryString('path', maxLen: 4096);
        $file = $this->fs->resolveDownload($path);

        header('X-Content-Type-Options: nosniff');
        header('Content-Type: ' . $file['mime']);
        header('Content-Length: ' . (string)$file['size']);
        header('Content-Disposition: attachment; filename="' . $this->headerFilename($file['name']) . '"');

        while (ob_get_level() > 0) {
            ob_end_clean();
        }

        try {
            $fp = fopen($file['abs'], 'rb');
            if ($fp === false) {
                http_response_code(403);
                echo 'File not readable.';
                exit;
            }

            try {
                $chunk = 1024 * 1024;
                while (!feof($fp)) {
                    $buf = fread($fp, $chunk);
                    if ($buf === false) {
                        break;
                    }
                    echo $buf;
                    flush();
                }
            } finally {
                fclose($fp);
            }
        } catch (ErrorException) {
            http_response_code(403);
            echo 'File not readable.';
            exit;
        }

        exit;
    }

    #[RequiresAuth]
    #[RequiresCsrf]
    #[RateLimited(key: 'upload', limit: 20, windowSeconds: 60)]
    public function upload(): array
    {
        $dir = $this->readPostString('dir', maxLen: 2048, allowEmpty: true);
        $file = $_FILES['file'] ?? null;
        if (!is_array($file)) {
            throw new AppException('Missing file upload', httpStatus: 400, publicMessage: 'No file uploaded.');
        }
        $result = $this->fs->upload($dir, $file);
        return ['ok' => true, 'data' => $result];
    }

    #[RequiresAuth]
    #[RequiresCsrf]
    #[RateLimited(key: 'mkdir', limit: 30, windowSeconds: 60)]
    public function mkdir(): array
    {
        $dir = $this->readPostString('dir', maxLen: 2048, allowEmpty: true);
        $name = $this->readPostString('name', maxLen: 255);
        $this->fs->mkdir($dir, $name);
        return ['ok' => true];
    }

    #[RequiresAuth]
    #[RequiresCsrf]
    #[RateLimited(key: 'rename', limit: 30, windowSeconds: 60)]
    public function rename(): array
    {
        $src = $this->readPostString('src', maxLen: 4096);
        $dst = $this->readPostString('dst', maxLen: 4096);
        $result = $this->fs->renameOrMove($src, $dst);
        return ['ok' => true, 'data' => $result];
    }

    #[RequiresAuth]
    #[RequiresCsrf]
    #[RateLimited(key: 'copy', limit: 20, windowSeconds: 60)]
    public function copy(): array
    {
        $src = $this->readPostString('src', maxLen: 4096);
        $dst = $this->readPostString('dst', maxLen: 4096);
        $this->fs->copyPath($src, $dst);
        return ['ok' => true];
    }

    #[RequiresAuth]
    #[RequiresCsrf]
    #[RateLimited(key: 'delete', limit: 20, windowSeconds: 60)]
    public function delete(): array
    {
        $path = $this->readPostString('path', maxLen: 4096);
        $this->fs->deletePath($path);
        return ['ok' => true];
    }

    #[RequiresAuth]
    #[RequiresCsrf]
    #[RateLimited(key: 'chmod', limit: 30, windowSeconds: 60)]
    public function chmod(): array
    {
        $path = $this->readPostString('path', maxLen: 4096);
        $modeRaw = $this->readPostString('mode', maxLen: 16);
        $recursive = $this->readPostString('recursive', maxLen: 8, allowEmpty: true);

        if (preg_match('/^[0-7]{3,4}$/', $modeRaw) !== 1) {
            throw new AppException('Invalid chmod mode', httpStatus: 400, publicMessage: 'Invalid permission mode. Use 755 or 0755.');
        }
        $mode = intval($modeRaw, 8);
        $this->fs->chmodPath($path, $mode, $recursive === '1');
        return ['ok' => true];
    }

    #[RequiresAuth]
    #[RequiresCsrf]
    #[RateLimited(key: 'zipCreate', limit: 10, windowSeconds: 60)]
    public function zipCreate(): array
    {
        $src = $this->readPostString('src', maxLen: 4096);
        $dst = $this->readPostString('dst', maxLen: 4096, allowEmpty: true);
        $level = $this->readPostString('level', maxLen: 16, allowEmpty: true);
        $progressId = $this->readPostString('progress_id', maxLen: 128, allowEmpty: true);

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }

        $result = $this->fs->zipCreate($src, $dst, $level, $progressId !== '' ? $progressId : null);
        return ['ok' => true, 'data' => $result];
    }

    #[RequiresAuth]
    #[RequiresCsrf]
    #[RateLimited(key: 'zipExtract', limit: 10, windowSeconds: 60)]
    public function zipExtract(): array
    {
        $zip = $this->readPostString('zip', maxLen: 4096);
        $dest = $this->readPostString('dest', maxLen: 2048, allowEmpty: true);
        $password = $this->readPostString('password', maxLen: 256, allowEmpty: true, trim: false);
        $recursive = $this->readPostString('recursive', maxLen: 8, allowEmpty: true);
        $progressId = $this->readPostString('progress_id', maxLen: 128, allowEmpty: true);

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }

        $result = $this->fs->zipExtract($zip, $dest, $password, $recursive === '1', $progressId !== '' ? $progressId : null);
        return ['ok' => true, 'data' => $result];
    }

    #[RequiresAuth]
    #[RequiresCsrf]
    #[RateLimited(key: 'zipProgress', limit: 120, windowSeconds: 60)]
    public function zipProgress(): array
    {
        $progressId = $this->readPostString('progress_id', maxLen: 128);
        $data = $this->fs->zipProgress($progressId);
        return ['ok' => true, 'data' => $data];
    }

    #[RequiresAuth]
    #[RequiresCsrf]
    #[RateLimited(key: 'pw', limit: 6, windowSeconds: 600)]
    public function changePassword(): array
    {
        $current = $this->readPostString('current', maxLen: 256, allowEmpty: true, trim: false);
        $next = $this->readPostString('next', maxLen: 256, allowEmpty: true, trim: false);
        $confirm = $this->readPostString('confirm', maxLen: 256, allowEmpty: true, trim: false);

        if ($current === '') {
            throw new AppException('Empty current password', httpStatus: 400, publicMessage: 'Current password is required.');
        }
        if ($next === '') {
            throw new AppException('Empty new password', httpStatus: 400, publicMessage: 'New password is required.');
        }
        if ($confirm === '') {
            throw new AppException('Empty confirm password', httpStatus: 400, publicMessage: 'Confirm password is required.');
        }
        if (!hash_equals($next, $confirm)) {
            throw new AppException('Password confirm mismatch', httpStatus: 400, publicMessage: 'New passwords do not match.');
        }
        $this->security->changePassword($current, $next);
        return ['ok' => true];
    }

    private function readPostString(string $key, int $maxLen, bool $allowEmpty = false, bool $trim = true): string
    {
        $val = $_POST[$key] ?? '';
        if (!is_string($val)) {
            throw new AppException('Invalid POST type', httpStatus: 400, publicMessage: 'Invalid request.');
        }
        $val = $trim ? trim($val) : $val;
        if (!$allowEmpty && $val === '') {
            throw new AppException('Missing POST field: ' . $key, httpStatus: 400, publicMessage: 'Missing field.');
        }
        if (strlen($val) > $maxLen) {
            throw new AppException('POST field too long: ' . $key, httpStatus: 400, publicMessage: 'Field too long.');
        }
        return $val;
    }

    private function readQueryString(string $key, int $maxLen, bool $allowEmpty = false): string
    {
        $val = $_GET[$key] ?? '';
        if (!is_string($val)) {
            throw new AppException('Invalid query type', httpStatus: 400, publicMessage: 'Invalid request.');
        }
        $val = trim($val);
        if (!$allowEmpty && $val === '') {
            throw new AppException('Missing query field: ' . $key, httpStatus: 400, publicMessage: 'Missing field.');
        }
        if (strlen($val) > $maxLen) {
            throw new AppException('Query field too long: ' . $key, httpStatus: 400, publicMessage: 'Field too long.');
        }
        return $val;
    }

    private function headerFilename(string $name): string
    {
        $clean = preg_replace('/[\r\n"]/','', $name) ?? $name;
        return $clean;
    }
}

final class App
{
    private const BASE_DIR = __DIR__;
    private const NOTE_FILE = __DIR__ . DIRECTORY_SEPARATOR . 'note.dat';
    private const IDLE_TIMEOUT_SECONDS = 900;

    private readonly NoteStore $note;
    private readonly Security $security;
    private readonly FsService $fs;
    private readonly Actions $actions;

    public function __construct()
    {
        $this->note = new NoteStore(self::NOTE_FILE);
        $this->security = new Security($this->note, self::IDLE_TIMEOUT_SECONDS);
        $this->fs = new FsService(self::BASE_DIR, [basename(__FILE__), 'note.dat']);
        $this->actions = new Actions($this->security, $this->fs);
    }

    public function run(): void
    {
        $this->configurePhp();
        $this->security->startSession();
        $this->security->enforceIdleTimeout();

        $action = $_GET['action'] ?? '';
        if (is_string($action) && $action !== '') {
            $this->handleAction($action);
            return;
        }

        $this->renderPage();
    }

    private function configurePhp(): void
    {
        error_reporting(E_ALL);
        ini_set('display_errors', '0');
        ini_set('display_startup_errors', '0');

        set_error_handler(
            static function (int $severity, string $message, string $file, int $line): never {
                if (DEBUG_MODE) {
                    $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
                    array_shift($trace);
                    debugLogError(
                        $message . ' in ' . $file . ':' . $line,
                        'PHP_' . debugPhpErrorName($severity),
                        debugFormatBacktrace($trace),
                    );
                }
                throw new ErrorException($message, 0, $severity, $file, $line);
            },
        );
    }

    private function handleAction(string $action): void
    {
        $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $nonce = bin2hex(random_bytes(12));
        $this->sendSecurityHeaders($nonce);

        try {
            $methodName = match ($action) {
                'login' => 'login',
                'logout' => 'logout',
                'list' => 'list',
                'upload' => 'upload',
                'mkdir' => 'mkdir',
                'rename' => 'rename',
                'copy' => 'copy',
                'delete' => 'delete',
                'chmod' => 'chmod',
                'zipCreate' => 'zipCreate',
                'zipExtract' => 'zipExtract',
                'zipProgress' => 'zipProgress',
                'changePassword' => 'changePassword',
                'download' => 'download',
                default => '',
            };

            if ($methodName === '') {
                throw new AppException('Unknown action', httpStatus: 404, publicMessage: 'Not found.');
            }

            $ref = new ReflectionMethod($this->actions, $methodName);
            $this->enforceAttributes($ref);

            if ($methodName === 'download') {
                if ($method !== 'GET') {
                    throw new AppException('Download requires GET', httpStatus: 405, publicMessage: 'Method not allowed.');
                }
                $this->actions->download();
            }

            if (in_array($methodName, ['list'], true)) {
                if ($method !== 'GET') {
                    throw new AppException('GET required', httpStatus: 405, publicMessage: 'Method not allowed.');
                }
            } else {
                if ($method !== 'POST') {
                    throw new AppException('POST required', httpStatus: 405, publicMessage: 'Method not allowed.');
                }
            }

            $result = $this->actions->{$methodName}();
            $this->sendJson($result);
        } catch (AppException $e) {
            if (DEBUG_MODE) {
                debugLogThrowable($e);
            }
            $lockMeta = null;
            try {
                $lockMeta = $this->security->lockState();
            } catch (Throwable) {
                $lockMeta = null;
            }
            $status = (property_exists($e, 'httpStatus') && is_int($e->httpStatus)) ? $e->httpStatus : 400;
            $msg = (property_exists($e, 'publicMessage') && is_string($e->publicMessage) && $e->publicMessage !== '')
                ? $e->publicMessage
                : 'Request failed.';

            $meta = [
                'locked' => $lockMeta,
            ];
            if (property_exists($e, 'errorCode') && is_int($e->errorCode)) {
                $meta['code'] = $e->errorCode;
            }
            if (property_exists($e, 'detail') && is_string($e->detail) && $e->detail !== '') {
                $meta['detail'] = $e->detail;
            }
            $this->sendJson([
                'ok' => false,
                'error' => $msg,
                'meta' => $meta,
            ], $status);
        } catch (Throwable $e) {
            if (DEBUG_MODE) {
                debugLogThrowable($e);
            }
            $this->sendJson([
                'ok' => false,
                'error' => 'Request failed.',
            ], 500);
        }
    }

    private function enforceAttributes(ReflectionMethod $method): void
    {
        $requiresAuth = $method->getAttributes(RequiresAuth::class);
        if (count($requiresAuth) > 0 && !$this->security->isAuthed()) {
            throw new AppException('Auth required', httpStatus: 401, publicMessage: 'Please log in.');
        }

        $requiresCsrf = $method->getAttributes(RequiresCsrf::class);
        if (count($requiresCsrf) > 0) {
            $this->security->requireCsrf();
        }

        $rate = $method->getAttributes(RateLimited::class);
        foreach ($rate as $attr) {
            /** @var RateLimited $cfg */
            $cfg = $attr->newInstance();
            $this->security->rateLimit($cfg->key, $cfg->limit, $cfg->windowSeconds);
        }
    }

    private function renderPage(): void
    {
        $nonce = bin2hex(random_bytes(12));
        $this->sendSecurityHeaders($nonce);

        try {
            $lock = $this->security->lockState();
            $csrf = $this->security->csrfToken();
            $authed = $this->security->isAuthed();
            $title = 'Tiny File Manager';

            header('Content-Type: text/html; charset=UTF-8');

            echo '<!doctype html>';
            echo '<html lang="en">';
            echo '<head>';
            echo '<meta charset="utf-8">';
            echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
            echo '<meta name="referrer" content="no-referrer">';
            echo '<title>' . htmlspecialchars($title, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</title>';
            echo '<style nonce="' . htmlspecialchars($nonce, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">' . $this->css() . '</style>';
            echo '</head>';
            echo '<body>';

            if (!$authed) {
                $this->renderLogin($csrf, $lock);
            } else {
                $this->renderManager($csrf);
            }

            echo '<script nonce="' . htmlspecialchars($nonce, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">' . $this->js($csrf) . '</script>';
            echo '</body>';
            echo '</html>';
        } catch (Throwable $e) {
            if (DEBUG_MODE) {
                debugLogThrowable($e);
            }
            http_response_code(500);
            header('Content-Type: text/plain; charset=UTF-8');
            echo 'Server error.';
        }
    }

    /** @param array{locked:bool, lock_until:int, remaining:int} $lock */
    private function renderLogin(string $csrf, array $lock): void
    {
        echo '<div class="loginWrap">';
        echo '<div class="card">';
        echo '<div class="cardHeader">';
        echo '<div class="h1">Tiny File Manager</div>';
        echo '<div class="muted">Authorized access only.</div>';
        echo '</div>';

        echo '<form id="loginForm" class="form" method="post" autocomplete="off">';
        echo '<input type="hidden" name="csrf" value="' . htmlspecialchars($csrf, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">';
        echo '<label class="label" for="pw">Password</label>';
        echo '<input id="pw" class="input" type="password" name="password" autofocus required maxlength="256">';
        echo '<button class="btn primary" type="submit">Unlock</button>';
        echo '<div id="loginStatus" class="status" aria-live="polite"></div>';

        if ($lock['locked']) {
            echo '<div class="inlineWarn errorText">Temporarily locked. Try again in ' . (int)$lock['remaining'] . 's.</div>';
        }

        echo '<div class="tiny muted">Idle timeout: ' . (int)self::IDLE_TIMEOUT_SECONDS . ' seconds.</div>';
        echo '</form>';

        echo '</div>';
        echo '</div>';
    }

    private function renderManager(string $csrf): void
    {
        echo '<div class="app">';
        echo '<header class="topbar">';
        echo '<div class="brand">Tiny File Manager</div>';
        echo '<nav class="crumbs" id="crumbs" aria-label="Breadcrumb"></nav>';
        echo '<div class="topActions">';
        echo '<button class="btn" id="btnChangePw" type="button">Change password</button>';
        echo '<button class="btn danger" id="btnLogout" type="button">Logout</button>';
        echo '</div>';
        echo '</header>';

        echo '<main class="main">';
        echo '<section class="toolbar">';
        echo '<div class="toolbarLeft">';
        echo '<button class="btn" id="btnUp" type="button">Up</button>';
        echo '<button class="btn" id="btnRefresh" type="button">Refresh</button>';
        echo '</div>';
        echo '<div class="toolbarRight">';
        echo '<button class="btn" id="btnMkdir" type="button">New folder</button>';
        echo '<input id="fileInput" class="hidden" type="file">';
        echo '<button class="btn primary" id="btnUpload" type="button">Upload</button>';
        echo '</div>';
        echo '</section>';

        echo '<section class="panel">';
        echo '<div class="panelHeader">';
        echo '<div class="pathLine"><span class="muted">Path:</span> <span id="pathText" class="mono"></span></div>';
        echo '<div class="progressWrap hidden" id="uploadProgressWrap">';
        echo '<div class="progressLabel" id="uploadProgressLabel">Uploading…</div>';
        echo '<div class="progressBar"><div class="progressFill" id="uploadProgressFill"></div></div>';
        echo '</div>';
        echo '</div>';
        echo '<div class="tableWrap">';
        echo '<table class="table" role="grid">';
        echo '<thead><tr><th>Name</th><th class="right">Size</th><th class="right">Modified</th><th class="right">Actions</th></tr></thead>';
        echo '<tbody id="fileTbody"></tbody>';
        echo '</table>';
        echo '<div class="empty hidden" id="emptyState">This folder is empty.</div>';
        echo '</div>';
        echo '</section>';
        echo '</main>';

        echo '<div class="toastHost" id="toastHost" aria-live="polite"></div>';

        echo '<div class="modal hidden" id="modal">';
        echo '<div class="modalCard">';
        echo '<div class="modalTitle" id="modalTitle"></div>';
        echo '<div class="modalBody" id="modalBody"></div>';
        echo '<div class="modalActions" id="modalActions"></div>';
        echo '</div>';
        echo '</div>';

        echo '<input type="hidden" id="csrf" value="' . htmlspecialchars($csrf, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '">';
        echo '</div>';
    }

    private function sendJson(array $payload, int $status = 200): void
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode($payload, flags: JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    private function sendSecurityHeaders(string $nonce): void
    {
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('X-Content-Type-Options: nosniff');
        header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
        header('Cache-Control: no-store, max-age=0');

        $csp = "default-src 'none'; "
            . "img-src 'self' data:; "
            . "style-src 'self' 'nonce-{$nonce}'; "
            . "script-src 'self' 'nonce-{$nonce}'; "
            . "connect-src 'self'; "
            . "base-uri 'none'; "
            . "form-action 'self'; "
            . "frame-ancestors 'none'";
        header('Content-Security-Policy: ' . $csp);
    }

    private function css(): string
    {
        return <<<CSS
        :root{--bg:#0b1220;--surface:#111a2e;--surface2:#0f1730;--text:#e6eefc;--muted:#93a4c7;--accent:#4ea1ff;--danger:#ff5a6a;--border:rgba(255,255,255,.08);--shadow:0 10px 30px rgba(0,0,0,.35);--radius:14px;--space:8px;}
        *{box-sizing:border-box;}
        body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;background:var(--bg);color:var(--text);}
        .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;}
        .muted{color:var(--muted);}
        .hidden{display:none!important;}
        .right{text-align:right;}

        .loginWrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}
        .card{width:100%;max-width:420px;background:linear-gradient(180deg,var(--surface),var(--surface2));border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);padding:24px;}
        .cardHeader{margin-bottom:16px;}
        .h1{font-size:20px;font-weight:650;letter-spacing:.2px;}
        .form{display:flex;flex-direction:column;gap:12px;}
        .label{font-size:12px;color:var(--muted);}
        .input{width:100%;padding:12px 12px;border-radius:12px;border:1px solid var(--border);background:rgba(255,255,255,.02);color:var(--text);outline:none;}
        .input:focus{border-color:rgba(78,161,255,.55);box-shadow:0 0 0 3px rgba(78,161,255,.18);}
        .btn{border:1px solid var(--border);background:rgba(255,255,255,.04);color:var(--text);padding:10px 12px;border-radius:12px;cursor:pointer;transition:transform .05s ease,background .15s ease,box-shadow .15s ease;}
        .btn:hover{background:rgba(255,255,255,.06);box-shadow:0 6px 16px rgba(0,0,0,.18);}
        .btn:active{transform:translateY(1px);}
        .btn.primary{background:rgba(78,161,255,.14);border-color:rgba(78,161,255,.35);}
        .btn.primary:hover{background:rgba(78,161,255,.18);}
        .btn.danger{background:rgba(255,90,106,.12);border-color:rgba(255,90,106,.28);}
        .btn.danger:hover{background:rgba(255,90,106,.16);}
        .status{min-height:18px;font-size:13px;color:var(--muted);}
        .inlineWarn{font-size:13px;color:rgba(255,255,255,.92);background:rgba(255,90,106,.14);border:1px solid rgba(255,90,106,.28);padding:10px 12px;border-radius:12px;}
        .errorText{color:#fff;font-weight:700;}
        .tiny{font-size:12px;}

        .app{min-height:100vh;display:flex;flex-direction:column;}
        .topbar{position:sticky;top:0;z-index:10;display:flex;align-items:center;gap:16px;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--border);background:rgba(11,18,32,.85);backdrop-filter:blur(10px);}
        .brand{font-size:16px;font-weight:650;}
        .crumbs{display:flex;gap:6px;flex-wrap:wrap;align-items:center;min-height:20px;}
        .crumb{font-size:12px;color:var(--muted);cursor:pointer;padding:6px 8px;border-radius:10px;border:1px solid transparent;}
        .crumb:hover{color:var(--text);border-color:var(--border);background:rgba(255,255,255,.04);}
        .crumbSep{color:rgba(147,164,199,.5);}
        .topActions{display:flex;gap:10px;}

        .main{padding:20px;display:flex;flex-direction:column;gap:16px;}
        .toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;}
        .toolbarLeft,.toolbarRight{display:flex;gap:10px;align-items:center;}
        .panel{background:linear-gradient(180deg,var(--surface),var(--surface2));border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);}
        .panelHeader{padding:16px 16px 0 16px;display:flex;align-items:flex-end;justify-content:space-between;gap:12px;flex-wrap:wrap;}
        .pathLine{font-size:13px;}
        .tableWrap{padding:16px;}
        .table{width:100%;border-collapse:separate;border-spacing:0 8px;}
        thead th{font-size:12px;color:var(--muted);font-weight:600;text-align:left;padding:0 12px;}
        tbody tr{background:rgba(255,255,255,.03);border:1px solid var(--border);}
        tbody td{padding:12px;border-top:1px solid var(--border);border-bottom:1px solid var(--border);}
        tbody td:first-child{border-left:1px solid var(--border);border-top-left-radius:12px;border-bottom-left-radius:12px;}
        tbody td:last-child{border-right:1px solid var(--border);border-top-right-radius:12px;border-bottom-right-radius:12px;}
        .nameCell{display:flex;gap:10px;align-items:center;min-width:160px;}
        .icon{width:26px;height:26px;border-radius:10px;display:flex;align-items:center;justify-content:center;background:rgba(78,161,255,.12);border:1px solid rgba(78,161,255,.22);color:rgba(230,238,252,.95);font-size:12px;}
        .icon.file{background:rgba(255,255,255,.06);border-color:rgba(255,255,255,.1);}
        .nameBtn{background:none;border:none;color:var(--text);cursor:pointer;padding:0;text-align:left;font:inherit;}
        .nameBtn:hover{text-decoration:underline;}
        .rowActions{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;}
        .btn.small{padding:8px 10px;border-radius:10px;font-size:12px;}
        .empty{padding:18px;border:1px dashed rgba(255,255,255,.14);border-radius:12px;color:var(--muted);}

        .toastHost{position:fixed;top:16px;right:16px;display:flex;flex-direction:column;gap:10px;z-index:50;}
        .toast{min-width:240px;max-width:360px;background:rgba(17,26,46,.98);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow);padding:12px 12px;font-size:13px;}
        .toast.ok{border-color:rgba(78,161,255,.28);}
        .toast.err{border-color:rgba(255,90,106,.35);}
        .toastTitle{font-weight:650;margin-bottom:2px;}
        .toastMsg{color:var(--muted);}
        .toast.err .toastTitle,.toast.err .toastMsg{color:#fff;font-weight:700;}

        .modal{position:fixed;inset:0;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;padding:18px;z-index:60;}
        .modalCard{width:100%;max-width:520px;background:linear-gradient(180deg,var(--surface),var(--surface2));border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);padding:18px;}
        .modalTitle{font-size:16px;font-weight:650;margin-bottom:10px;}
        .modalBody{display:flex;flex-direction:column;gap:10px;}
        .modalActions{margin-top:14px;display:flex;gap:10px;justify-content:flex-end;flex-wrap:wrap;}
        .help{font-size:12px;color:var(--muted);}
        .progressWrap{min-width:260px;}
        .progressLabel{font-size:12px;color:var(--muted);margin-bottom:6px;}
        .progressBar{width:100%;height:10px;border-radius:999px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.10);overflow:hidden;}
        .progressFill{height:100%;width:0%;background:linear-gradient(90deg,rgba(78,161,255,.75),rgba(78,161,255,.25));}

        @media (max-width: 760px){
            thead{display:none;}
            tbody td{display:block;border-left:1px solid var(--border);border-right:1px solid var(--border);}
            tbody td:first-child{border-top-left-radius:12px;border-top-right-radius:12px;border-bottom-left-radius:0;}
            tbody td:last-child{border-bottom-left-radius:12px;border-bottom-right-radius:12px;border-top-right-radius:0;}
            .rowActions{justify-content:flex-start;}
        }
        @media (max-width: 480px){
            .errorText{color:#fff;font-weight:700;}
            .toast.err .toastTitle,.toast.err .toastMsg{color:#fff;font-weight:700;}
        }
        CSS;
    }

    private function js(string $csrf): string
    {
        $csrfJs = json_encode($csrf, flags: JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $rootRelJs = json_encode($this->fs->rootRel(), flags: JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return <<<JS
        (function(){
          const CSRF = {$csrfJs} || '';
          const ROOT_REL = {$rootRelJs} || '';
          const byId = (id) => document.getElementById(id);
          const toastHost = byId('toastHost');
          const modal = byId('modal');
          const modalTitle = byId('modalTitle');
          const modalBody = byId('modalBody');
          const modalActions = byId('modalActions');

          function toast(type, title, msg){
            if(!toastHost) return;
            const el = document.createElement('div');
            el.className = 'toast ' + (type === 'err' ? 'err' : 'ok');
            const t = document.createElement('div');
            t.className = 'toastTitle';
            t.textContent = title;
            const m = document.createElement('div');
            m.className = 'toastMsg';
            m.textContent = msg;
            el.appendChild(t);
            el.appendChild(m);
            toastHost.appendChild(el);
            setTimeout(() => { el.remove(); }, 3200);
          }

          function showModal(title, bodyNodes, actions){
            modalTitle.textContent = title;
            modalBody.innerHTML = '';
            bodyNodes.forEach(n => modalBody.appendChild(n));
            modalActions.innerHTML = '';
            actions.forEach(a => modalActions.appendChild(a));
            modal.classList.remove('hidden');
          }

          function hideModal(){
            modal.classList.add('hidden');
          }

          if(modal){
            modal.addEventListener('click', (e) => {
              if(e.target === modal) hideModal();
            });
          }

          async function api(action, method, data){
            const url = new URL(window.location.href);
            url.searchParams.set('action', action);
            const opts = { method, credentials: 'same-origin', headers: { 'X-CSRF-Token': CSRF } };
            if(method === 'POST'){
              const body = new URLSearchParams();
              Object.entries(data || {}).forEach(([k,v]) => body.set(k, String(v)));
              opts.headers['Content-Type'] = 'application/x-www-form-urlencoded;charset=UTF-8';
              opts.body = body.toString();
            }
            const res = await fetch(url.toString(), opts);
            const json = await res.json().catch(() => null);
            if(!json || json.ok !== true){
              const msg = (json && json.error) ? json.error : 'Request failed.';
              throw new Error(msg);
            }
            return json.data;
          }

          const loginForm = byId('loginForm');
          if(loginForm){
            loginForm.addEventListener('submit', async (e) => {
              e.preventDefault();
              const status = byId('loginStatus');
              const pw = byId('pw');
              const fd = new FormData(loginForm);
              const payload = new URLSearchParams();
              payload.set('password', String(fd.get('password')||''));
              payload.set('csrf', String(fd.get('csrf')||''));
              status.textContent = 'Checking…';
              status.classList.remove('errorText');
              try{
                const url = new URL(window.location.href);
                url.searchParams.set('action', 'login');

                console.log('2241', payload);   // DBEUG

                const res = await fetch(url.toString(), {
                  method: 'POST',
                  credentials: 'same-origin',
                  headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
                  body: payload.toString(),
                });
                const json = await res.json().catch(() => null);
                
                console.log('2251', json);   // DBEUG

                if(!json || json.ok !== true){
                  const msg = (json && json.error) ? json.error : 'Invalid password or temporarily locked.';
                  status.textContent = msg;
                  status.classList.add('errorText');
                  if(pw) pw.value = '';
                  return;
                }
                window.location.reload();
              }catch(err){
                status.textContent = 'Request failed.';
                status.classList.add('errorText');
              }
            });
            return;
          }

          function normalizeDir(dir) {
            // PHP heredoc parses backslash escapes: use \\\\ here to emit \\ in JS and match "\" correctly.
            const raw = String(dir||'').replace(/\\\\/g,'/').replace(/^\/+/, '').replace(/\/+$/,'');
            if(!raw) return '';
            const parts = raw.split('/').filter(Boolean);
            const clean = [];
            for(const p of parts){
              if(p === '.' || p === '') continue;
              if(p === '..'){
                const last = clean.length ? clean[clean.length-1] : '';
                if(last && last !== '..'){ clean.pop(); }
                else clean.push('..');
                continue;
              }
              clean.push(p);
            }
            return clean.join('/');
          }

          let currentDir = '';
          let loadSeq = 0;
          let navSeq = 0;
          const tbody = byId('fileTbody');
          const emptyState = byId('emptyState');
          const pathText = byId('pathText');
          const crumbs = byId('crumbs');
          const btnUp = byId('btnUp');
          const btnRefresh = byId('btnRefresh');
          const btnMkdir = byId('btnMkdir');
          const btnUpload = byId('btnUpload');
          const fileInput = byId('fileInput');
          const btnLogout = byId('btnLogout');
          const btnChangePw = byId('btnChangePw');
          const upWrap = byId('uploadProgressWrap');
          const upFill = byId('uploadProgressFill');
          const upLabel = byId('uploadProgressLabel');

          function fmtSize(n){
            if(typeof n !== 'number' || !isFinite(n)) return '';
            const u = ['B','KB','MB','GB','TB'];
            let i = 0; let v = n;
            while(v >= 1024 && i < u.length-1){ v /= 1024; i++; }
            return (i===0? String(v): v.toFixed(1)) + ' ' + u[i];
          }
          function fmtTime(ts){
            if(!ts) return '';
            try{
              return new Date(ts*1000).toLocaleString();
            }catch(err){ return ''; }
          }
          function joinPath(dir, name){
            if(!dir) return name;
            return dir.replace(/\/+$/,'') + '/' + name;
          }
          function parentDir(dir){
            const d = normalizeDir(dir);
            if(d === ROOT_REL){
              return d;
            }
            if(!d){
              return '..';
            }
            return normalizeDir(d + '/..');
          }

          function renderCrumbs(){
            if(!crumbs) return;
            crumbs.innerHTML = '';
            const root = document.createElement('button');
            root.className = 'crumb';
            root.type = 'button';
            root.textContent = 'root';
            root.addEventListener('click', () => navigate(''));
            crumbs.appendChild(root);
            const parts = (currentDir||'').split('/').filter(Boolean);
            let acc = '';
            parts.forEach((p) => {
              const sep = document.createElement('span');
              sep.className = 'crumbSep';
              sep.textContent = '/';
              crumbs.appendChild(sep);
              acc = acc ? (acc + '/' + p) : p;
              const targetDir = acc;
              const btn = document.createElement('button');
              btn.className = 'crumb';
              btn.type = 'button';
              btn.textContent = p;
              btn.addEventListener('click', () => navigate(targetDir));
              crumbs.appendChild(btn);
            });
          }

          function rowIcon(type){
            const el = document.createElement('div');
            el.className = 'icon ' + (type === 'dir' ? 'dir' : 'file');
            el.textContent = type === 'dir' ? 'DIR' : 'FILE';
            return el;
          }

          function actionBtn(label, kind, onClick){
            const b = document.createElement('button');
            b.type = 'button';
            b.className = 'btn small' + (kind ? (' ' + kind) : '');
            b.textContent = label;
            b.addEventListener('click', onClick);
            return b;
          }

          function inputRow(label, type, value){
            const wrap = document.createElement('div');
            const l = document.createElement('div');
            l.className = 'label';
            l.textContent = label;
            const i = document.createElement('input');
            i.className = 'input';
            i.type = type;
            i.value = value || '';
            wrap.appendChild(l);
            wrap.appendChild(i);
            return { wrap, input: i };
          }

          function selectRow(label, options, value){
            const wrap = document.createElement('div');
            const l = document.createElement('div');
            l.className = 'label';
            l.textContent = label;
            const s = document.createElement('select');
            s.className = 'input';
            (options||[]).forEach((opt) => {
              const o = document.createElement('option');
              o.value = String(opt && opt.value !== undefined ? opt.value : '');
              o.textContent = String(opt && opt.label !== undefined ? opt.label : '');
              s.appendChild(o);
            });
            if(value !== undefined && value !== null){
              s.value = String(value);
            }
            wrap.appendChild(l);
            wrap.appendChild(s);
            return { wrap, select: s };
          }

          function sleep(ms){ return new Promise((r) => setTimeout(r, ms)); }

          async function runZipOperation(title, action, payload, doneTitle, doneMsg){
            const progressId = String(Date.now()) + '_' + Math.random().toString(16).slice(2);
            const status = document.createElement('div');
            status.className = 'help';
            status.textContent = 'Starting…';
            const barWrap = document.createElement('div');
            barWrap.className = 'progressWrap';
            const bar = document.createElement('div');
            bar.className = 'progressBar';
            bar.style.width = '0%';
            barWrap.appendChild(bar);
            const cancel = actionBtn('Close','',() => hideModal());
            showModal(title,[status,barWrap],[cancel]);

            const started = api(action,'POST', Object.assign({}, payload, { progress_id: progressId }));

            try{
              let lastState = '';
              while(true){
                const p = await api('zipProgress','POST',{ progress_id: progressId });
                const state = (p && typeof p.state === 'string') ? p.state : 'missing';
                const msg = (p && typeof p.message === 'string') ? p.message : '';
                const processed = (p && typeof p.processed === 'number') ? p.processed : 0;
                const total = (p && typeof p.total === 'number') ? p.total : 0;
                if(state !== lastState || msg){
                  status.textContent = msg || (state === 'running' ? 'Working…' : state);
                  lastState = state;
                }
                if(total > 0){
                  const pct = Math.max(0, Math.min(100, Math.floor((processed / total) * 100)));
                  bar.style.width = pct + '%';
                }
                if(state === 'done'){
                  break;
                }
                if(state === 'error'){
                  throw new Error(msg || 'ZIP operation failed.');
                }
                await sleep(350);
              }
              const result = await started;
              hideModal();
              toast('ok', doneTitle, doneMsg);
              const loadRes = await load();
              if(loadRes && loadRes.ok !== true && loadRes.canceled !== true){
                toast('err','Error', loadRes.error || 'Cannot load folder.');
              }
              return result;
            }catch(err){
              try{ await started; }catch(_e){}
              throw err;
            }
          }

          function zipCreateModal(srcPath, name){
            const dstRow = inputRow('Destination .zip (relative, optional)','text','');
            const levelRow = selectRow('Compression level', [
              { value: 'fast', label: 'Fast' },
              { value: 'normal', label: 'Normal' },
              { value: 'maximum', label: 'Maximum' },
            ], 'normal');
            const help = document.createElement('div');
            help.className = 'help';
            help.textContent = 'Create a .zip archive. Leave destination blank to create next to the source item.';
            const cancel = actionBtn('Cancel','',() => hideModal());
            const ok = actionBtn('Create ZIP','primary', async () => {
              ok.disabled = true;
              try{
                const dst = String(dstRow.input.value || '').trim();
                const level = String(levelRow.select.value || '').trim();
                hideModal();
                await runZipOperation('Creating ZIP…', 'zipCreate', { src: srcPath, dst, level }, 'Created', 'ZIP created.');
              }catch(err){
                toast('err','Error', String(err.message||'ZIP create failed.'));
              }finally{
                ok.disabled = false;
              }
            });
            showModal('Create ZIP: ' + name,[dstRow.wrap, levelRow.wrap, help],[cancel, ok]);
            dstRow.input.focus();
          }

          function zipExtractModal(zipPath, name){
            const destRow = inputRow('Destination folder (relative, optional)','text','');
            const pwRow = inputRow('Password (optional)','password','');
            const recWrap = document.createElement('div');
            const recLabel = document.createElement('label');
            recLabel.className = 'help';
            const rec = document.createElement('input');
            rec.type = 'checkbox';
            rec.style.marginRight = '8px';
            recLabel.appendChild(rec);
            recLabel.appendChild(document.createTextNode('Extract nested ZIPs (recursive)'));
            recWrap.appendChild(recLabel);
            const help = document.createElement('div');
            help.className = 'help';
            help.textContent = 'Extract this .zip archive. Leave destination blank to extract into the ZIP’s parent folder.';
            const cancel = actionBtn('Cancel','',() => hideModal());
            const ok = actionBtn('Extract','primary', async () => {
              ok.disabled = true;
              try{
                const dest = String(destRow.input.value || '').trim();
                const password = String(pwRow.input.value || '');
                const recursive = rec.checked ? '1' : '0';
                hideModal();
                await runZipOperation('Extracting ZIP…', 'zipExtract', { zip: zipPath, dest, password, recursive }, 'Extracted', 'ZIP extracted.');
              }catch(err){
                toast('err','Error', String(err.message||'ZIP extract failed.'));
              }finally{
                ok.disabled = false;
              }
            });
            showModal('Extract ZIP: ' + name,[destRow.wrap, pwRow.wrap, recWrap, help],[cancel, ok]);
            destRow.input.focus();
          }

          async function load(){
            if(!tbody) return { ok:false, canceled:false, error:'Cannot load folder.' };
            const seq = ++loadSeq;
            tbody.innerHTML = '';
            emptyState.classList.add('hidden');
            if(pathText) pathText.textContent = currentDir ? ('/' + currentDir) : '/';
            renderCrumbs();
            const url = new URL(window.location.href);
            url.searchParams.set('action','list');
            url.searchParams.set('dir', currentDir);
            let res;
            try{
              res = await fetch(url.toString(), { method:'GET', headers:{ 'X-CSRF-Token': CSRF } });
            }catch(err){
              return { ok:false, canceled: seq !== loadSeq, error:'Cannot load folder.' };
            }
            if(seq !== loadSeq) return { ok:false, canceled:true };
            const json = await res.json().catch(() => null);
            if(!res.ok || !json || json.ok !== true){
              const msg = (json && json.error) ? json.error : 'Cannot load folder.';
              return { ok:false, canceled:false, error:msg };
            }
            const serverDir = (json.data && typeof json.data.dir === 'string') ? normalizeDir(json.data.dir) : currentDir;
            if(serverDir !== currentDir){
              currentDir = serverDir;
              if(pathText) pathText.textContent = currentDir ? ('/' + currentDir) : '/';
              renderCrumbs();
            }
            if(btnUp) btnUp.disabled = (currentDir === ROOT_REL);
            const entries = (json.data && json.data.entries) ? json.data.entries : [];
            if(seq !== loadSeq) return { ok:false, canceled:true };
            if(!entries.length){
              emptyState.classList.remove('hidden');
              return { ok:true, canceled:false };
            }
            entries.forEach((e) => {
              const tr = document.createElement('tr');
              const tdName = document.createElement('td');
              const tdSize = document.createElement('td');
              const tdTime = document.createElement('td');
              const tdAct = document.createElement('td');
              tdSize.className = 'right';
              tdTime.className = 'right';
              tdAct.className = 'right';

              const nameWrap = document.createElement('div');
              nameWrap.className = 'nameCell';
              nameWrap.appendChild(rowIcon(e.type));
              const nameBtn = document.createElement('button');
              nameBtn.type = 'button';
              nameBtn.className = 'nameBtn';
              nameBtn.textContent = e.name;
              if(e.type === 'dir'){
                nameBtn.addEventListener('click', () => navigate(joinPath(currentDir, e.name)));
              }else{
                nameBtn.addEventListener('click', () => download(joinPath(currentDir, e.name)));
              }
              nameWrap.appendChild(nameBtn);
              tdName.appendChild(nameWrap);

              tdSize.textContent = e.type === 'file' ? fmtSize(e.size||0) : '';
              tdTime.textContent = fmtTime(e.mtime||0);

              const actions = document.createElement('div');
              actions.className = 'rowActions';
              if(e.type === 'dir'){
                actions.appendChild(actionBtn('Open','',() => navigate(joinPath(currentDir, e.name))));
                actions.appendChild(actionBtn('Zip','',() => zipCreateModal(joinPath(currentDir, e.name), e.name)));
              }else{
                actions.appendChild(actionBtn('Download','',() => download(joinPath(currentDir, e.name))));
                const isZip = String(e.name||'').toLowerCase().endsWith('.zip');
                if(isZip){
                  actions.appendChild(actionBtn('Extract','',() => zipExtractModal(joinPath(currentDir, e.name), e.name)));
                }else{
                  actions.appendChild(actionBtn('Zip','',() => zipCreateModal(joinPath(currentDir, e.name), e.name)));
                }
              }
              actions.appendChild(actionBtn('Rename/Move','',() => renameMoveModal(joinPath(currentDir, e.name), e.name)));
              actions.appendChild(actionBtn('Copy','',() => copyModal(joinPath(currentDir, e.name), e.name)));
              actions.appendChild(actionBtn('Chmod','',() => chmodModal(joinPath(currentDir, e.name))));
              actions.appendChild(actionBtn('Delete','danger',() => deleteConfirm(joinPath(currentDir, e.name), e.type)));
              tdAct.appendChild(actions);

              tr.appendChild(tdName);
              tr.appendChild(tdSize);
              tr.appendChild(tdTime);
              tr.appendChild(tdAct);
              tbody.appendChild(tr);
            });
            return { ok:true, canceled:false };
          }

          async function navigate(dir){
            const navId = ++navSeq;
            const prevDir = currentDir;
            currentDir = normalizeDir(dir);
            const loadRes = await load();
            if(navId !== navSeq) return;
            if(!loadRes || loadRes.ok !== true){
              if(loadRes && loadRes.canceled){
                return;
              }
              toast('err','Error', (loadRes && loadRes.error) ? loadRes.error : 'Cannot load folder.');
              currentDir = prevDir;
              const back = await load();
              if(navId !== navSeq) return;
              if(back && back.ok !== true && back.canceled !== true){
                toast('err','Error', back.error || 'Cannot load folder.');
              }
            }
          }

          function download(path){
            const url = new URL(window.location.href);
            url.searchParams.set('action','download');
            url.searchParams.set('path', path);
            window.location.href = url.toString();
          }

          function mkdirModal(){
            const folderRow = inputRow('Folder name','text','');
            const help = document.createElement('div');
            help.className = 'help';
            help.textContent = 'Create a new folder in the current directory.';
            const cancel = actionBtn('Cancel','',() => hideModal());
            const ok = actionBtn('Create','primary', async () => {
              ok.disabled = true;
              try{
                const name = (folderRow.input.value || '').trim();
                if(!name){
                  toast('err','Error','Folder name is required.');
                  return;
                }
                if(/[\\/]/.test(name)){
                  toast('err','Error','Invalid name. Do not include slashes.');
                  return;
                }
                await api('mkdir','POST',{ dir: currentDir, name });
                hideModal();
                toast('ok','Created','Folder created.');
                const loadRes = await load();
                if(loadRes && loadRes.ok !== true && loadRes.canceled !== true){
                  toast('err','Error', loadRes.error || 'Cannot load folder.');
                }
              }catch(err){
                toast('err','Error', String(err.message||'Create failed.'));
              }finally{
                ok.disabled = false;
              }
            });
            showModal('New folder',[folderRow.wrap,help],[cancel,ok]);
            folderRow.input.focus();
          }

          function renameMoveModal(srcPath, currentName){
            const destDirRow = inputRow('Destination folder (relative)','text', currentDir);
            const nameRow = inputRow('New name','text', currentName);
            const help = document.createElement('div');
            help.className = 'help';
            help.textContent = 'Move within the allowed base directory. Use a relative folder path.';
            const cancel = actionBtn('Cancel','',() => hideModal());
            const ok = actionBtn('Move','primary', async () => {
              try{
                const ddir = destDirRow.input.value.replace(/^\/+/, '').replace(/\/+$/,'');
                const dst = (ddir ? (ddir + '/' + nameRow.input.value) : nameRow.input.value);
                await api('rename','POST',{ src: srcPath, dst });
                hideModal();
                toast('ok','Moved','Item moved.');
                const loadRes = await load();
                if(loadRes && loadRes.ok !== true && loadRes.canceled !== true){
                  toast('err','Error', loadRes.error || 'Cannot load folder.');
                }
              }catch(err){
                toast('err','Error', String(err.message||'Move failed.'));
              }
            });
            showModal('Rename / Move',[destDirRow.wrap,nameRow.wrap,help],[cancel,ok]);
          }

          function copyModal(srcPath, currentName){
            const destDirRow = inputRow('Destination folder (relative)','text', currentDir);
            const nameRow = inputRow('Copy name','text', currentName);
            const help = document.createElement('div');
            help.className = 'help';
            help.textContent = 'Copy within the allowed base directory.';
            const cancel = actionBtn('Cancel','',() => hideModal());
            const ok = actionBtn('Copy','primary', async () => {
              try{
                const ddir = destDirRow.input.value.replace(/^\/+/, '').replace(/\/+$/,'');
                const dst = (ddir ? (ddir + '/' + nameRow.input.value) : nameRow.input.value);
                await api('copy','POST',{ src: srcPath, dst });
                hideModal();
                toast('ok','Copied','Item copied.');
                const loadRes = await load();
                if(loadRes && loadRes.ok !== true && loadRes.canceled !== true){
                  toast('err','Error', loadRes.error || 'Cannot load folder.');
                }
              }catch(err){
                toast('err','Error', String(err.message||'Copy failed.'));
              }
            });
            showModal('Copy',[destDirRow.wrap,nameRow.wrap,help],[cancel,ok]);
          }

          function chmodModal(path){
            const modeRow = inputRow('Mode (e.g. 755 or 0755)','text','755');
            const recWrap = document.createElement('div');
            const recLabel = document.createElement('label');
            recLabel.className = 'help';
            const rec = document.createElement('input');
            rec.type = 'checkbox';
            rec.style.marginRight = '8px';
            recLabel.appendChild(rec);
            recLabel.appendChild(document.createTextNode('Apply recursively (folders only)'));
            recWrap.appendChild(recLabel);
            const cancel = actionBtn('Cancel','',() => hideModal());
            const ok = actionBtn('Apply','primary', async () => {
              try{
                await api('chmod','POST',{ path, mode: modeRow.input.value, recursive: rec.checked ? '1' : '0' });
                hideModal();
                toast('ok','Updated','Permissions updated.');
                const loadRes = await load();
                if(loadRes && loadRes.ok !== true && loadRes.canceled !== true){
                  toast('err','Error', loadRes.error || 'Cannot load folder.');
                }
              }catch(err){
                toast('err','Error', String(err.message||'Chmod failed.'));
              }
            });
            showModal('Change permissions',[modeRow.wrap,recWrap],[cancel,ok]);
          }

          function deleteConfirm(path, type){
            const msg = document.createElement('div');
            msg.className = 'inlineWarn';
            msg.textContent = type === 'dir' ? 'Delete this folder and all its contents?' : 'Delete this file?';
            const help = document.createElement('div');
            help.className = 'help';
            help.textContent = 'This action cannot be undone.';
            const cancel = actionBtn('Cancel','',() => hideModal());
            const ok = actionBtn('Delete','danger', async () => {
              try{
                await api('delete','POST',{ path });
                hideModal();
                toast('ok','Deleted','Item deleted.');
                const loadRes = await load();
                if(loadRes && loadRes.ok !== true && loadRes.canceled !== true){
                  toast('err','Error', loadRes.error || 'Cannot load folder.');
                }
              }catch(err){
                toast('err','Error', String(err.message||'Delete failed.'));
              }
            });
            showModal('Confirm delete',[msg,help],[cancel,ok]);
          }

          function changePwModal(){
            const cur = inputRow('Current password','password','');
            const next = inputRow('New password','password','');
            const conf = inputRow('Confirm new password','password','');
            const help = document.createElement('div');
            help.className = 'help';
            help.textContent = 'Pick a strong password and store it safely.';
            const cancel = actionBtn('Cancel','',() => hideModal());
            const ok = actionBtn('Change','primary', async () => {
              try{
                await api('changePassword','POST',{ current: cur.input.value, next: next.input.value, confirm: conf.input.value });
                hideModal();
                toast('ok','Updated','Password updated.');
              }catch(err){
                toast('err','Error', String(err.message||'Password change failed.'));
              }
            });
            showModal('Change password',[cur.wrap,next.wrap,conf.wrap,help],[cancel,ok]);
          }

          function setUploadProgress(on, pct, label){
            if(!upWrap) return;
            if(!on){
              upWrap.classList.add('hidden');
              if(upFill) upFill.style.width = '0%';
              if(upLabel) upLabel.textContent = 'Uploading…';
              return;
            }
            upWrap.classList.remove('hidden');
            if(upFill) upFill.style.width = String(Math.max(0,Math.min(100,pct||0))) + '%';
            if(upLabel && label) upLabel.textContent = label;
          }

          function uploadFile(file){
            return new Promise((resolve,reject) => {
              const url = new URL(window.location.href);
              url.searchParams.set('action','upload');
              const xhr = new XMLHttpRequest();
              xhr.open('POST', url.toString(), true);
              xhr.setRequestHeader('X-CSRF-Token', CSRF);
              xhr.upload.onprogress = (e) => {
                if(!e.lengthComputable) return;
                const pct = Math.round((e.loaded / e.total) * 100);
                setUploadProgress(true, pct, 'Uploading… ' + pct + '%');
              };
              xhr.onload = () => {
                setUploadProgress(false, 0, '');
                try{
                  const json = JSON.parse(xhr.responseText||'{}');
                  if(json && json.ok === true) return resolve(json.data);
                  const msg = (json && json.error) ? json.error : 'Upload failed.';
                  reject(new Error(msg));
                }catch(err){ reject(new Error('Upload failed.')); }
              };
              xhr.onerror = () => { setUploadProgress(false,0,''); reject(new Error('Upload failed.')); };
              const fd = new FormData();
              fd.append('dir', currentDir);
              fd.append('file', file);
              xhr.send(fd);
              setUploadProgress(true, 0, 'Starting upload…');
            });
          }

          if(btnUp){
            btnUp.addEventListener('click', () => {
              if(currentDir === ROOT_REL){
                toast('err','Error','Already at filesystem root.');
                return;
              }
              navigate(parentDir(currentDir));
            });
          }
          if(btnRefresh){
            btnRefresh.addEventListener('click', async () => {
              const loadRes = await load();
              if(loadRes && loadRes.ok !== true && loadRes.canceled !== true){
                toast('err','Error', loadRes.error || 'Cannot load folder.');
              }
            });
          }
          if(btnMkdir){ btnMkdir.addEventListener('click', () => mkdirModal()); }
          if(btnUpload){
            btnUpload.addEventListener('click', () => { if(fileInput) fileInput.click(); });
          }
          if(fileInput){
            fileInput.addEventListener('change', async () => {
              const f = fileInput.files && fileInput.files[0];
              if(!f) return;
              try{
                await uploadFile(f);
                toast('ok','Uploaded','Upload completed.');
                const loadRes = await load();
                if(loadRes && loadRes.ok !== true && loadRes.canceled !== true){
                  toast('err','Error', loadRes.error || 'Cannot load folder.');
                }
              }catch(err){
                toast('err','Error', String(err.message||'Upload failed.'));
              }finally{
                fileInput.value = '';
              }
            });
          }
          if(btnLogout){
            btnLogout.addEventListener('click', async () => {
              try{
                await api('logout','POST',{});
                window.location.reload();
              }catch(err){
                toast('err','Error', String(err.message||'Logout failed.'));
              }
            });
          }
          if(btnChangePw){ btnChangePw.addEventListener('click', () => changePwModal()); }

          navigate('');
        })();
        JS;
    }
}

// Only run if called directly, not when included for testing
if (!defined('TESTING')) {
    (new App())->run();
}
