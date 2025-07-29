Long Script Version:
function Scan-Port {
    param(
        [string]$target,
        [int]$startPort,
        [int]$endPort
    )
    
    $timeout = 2000
    Write-Host "Scanning ports from $startPort to $endPort on $target"

    for ($port = $startPort; $port -le $endPort; $port++) {
        $client = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $client.BeginConnect($target, $port, $null, $null)
        $waitHandle = $asyncResult.AsyncWaitHandle

        if ($waitHandle.WaitOne($timeout, $false)) {
            if ($client.Connected) {
                Write-Host "Port $port is open" -ForegroundColor Green
                $client.Close()
            } else {
                Write-Host "Port $port is closed" -ForegroundColor Red
            }
        } else {
            Write-Host "Port $port is closed (Timeout)" -ForegroundColor Red
        }

        $waitHandle.Close()
    }
}

# Usage
# Replace '192.168.1.1' with the target IP address, and set the desired port range
Scan-Port -target "192.168.1.1" -startPort 1 -endPort 1024
