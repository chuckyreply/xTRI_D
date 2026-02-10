<?php
header("Content-Type: text/plain");
echo "=== PHP LAB DIAGNOSTIC ===\n\n";

/* -------------------------
   BASIC SERVER INFO
------------------------- */
echo "[SERVER INFO]\n";
echo "Hostname        : " . gethostname() . "\n";
echo "OS              : " . php_uname() . "\n";
echo "PHP Version     : " . PHP_VERSION . "\n";
echo "SAPI            : " . php_sapi_name() . "\n";
echo "User            : " . get_current_user() . "\n";
echo "Document Root   : " . ($_SERVER['DOCUMENT_ROOT'] ?? '-') . "\n";
echo "\n";

/* -------------------------
   DISABLED FUNCTIONS
------------------------- */
echo "[PHP FUNCTIONS]\n";
$disabled = ini_get("disable_functions");
if ($disabled) {
    echo "disable_functions: $disabled\n";
} else {
    echo "disable_functions: NONE\n";
}

$funcs = ["exec", "system", "shell_exec", "passthru", "popen"];
foreach ($funcs as $f) {
    echo str_pad($f, 15) . ": " . (function_exists($f) ? "ENABLED" : "DISABLED") . "\n";
}
echo "\n";

/* -------------------------
   NETCAT CHECK
------------------------- */
echo "[NETCAT CHECK]\n";

function cmd_exists($cmd) {
    $out = shell_exec("command -v $cmd 2>/dev/null");
    return !empty($out);
}

if (function_exists("shell_exec")) {
    if (cmd_exists("nc")) {
        echo "netcat (nc)      : FOUND\n";
    } elseif (cmd_exists("ncat")) {
        echo "ncat             : FOUND\n";
    } elseif (cmd_exists("netcat")) {
        echo "netcat           : FOUND\n";
    } else {
        echo "netcat           : NOT FOUND\n";
    }
} else {
    echo "shell_exec       : DISABLED (cannot check nc)\n";
}
echo "\n";

/* -------------------------
   OUTBOUND CONNECT TEST
------------------------- */
echo "[OUTBOUND TEST]\n";
$test_host = "8.8.8.8";
$test_port = 53;

$fp = @fsockopen($test_host, $test_port, $errno, $errstr, 5);
if ($fp) {
    echo "Outbound TCP     : ALLOWED ($test_host:$test_port)\n";
    fclose($fp);
} else {
    echo "Outbound TCP     : BLOCKED ($errno - $errstr)\n";
}
echo "\n";

/* -------------------------
   PERMISSION CHECK
------------------------- */
echo "[PERMISSION]\n";
$tmp = "/tmp/php_test_" . uniqid();
if (@file_put_contents($tmp, "test")) {
    echo "Write /tmp       : OK\n";
    unlink($tmp);
} else {
    echo "Write /tmp       : FAILED\n";
}

echo "\n=== END DIAGNOSTIC ===\n";
?>
