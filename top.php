<?php
$fp = fsockopen("google.com", 80, $e, $s, 5);
var_dump($fp);
?>
