function Test-Port {
    param(
        [string]$ip,
        [int]$port = 80,
        [int]$timeout = 100
    )
    $connection = New-Object System.Net.Sockets.TcpClient
    $connection.ReceiveTimeout = $timeout
    $connection.SendTimeout = $timeout
    try {
        $asyncResult = $connection.BeginConnect($ip, $port, $null, $null)
        $waitHandle = $asyncResult.AsyncWaitHandle
        if ($waitHandle.WaitOne($timeout, $true)) {
            $connection.EndConnect($asyncResult) | Out-Null
            $connection.Close()
            return $true
        }
    } catch {
        # Ignore exceptions, treat as closed port
    }
    return $false
}
function Find-LiveHosts {
    param(
        [string]$subnet,
        [int]$startIP,
        [int]$endIP,
        [int[]]$portsToCheck
    )
    for ($i = $startIP; $i -le $endIP; $i++) {
        $ip = "$subnet$i"
        foreach ($port in $portsToCheck) {
            if (Test-Port -ip $ip -port $port) {
                Write-Host "$ip on port $port is live" -ForegroundColor Green
                break
            }
        }
    }
}
# Usage
Find-LiveHosts -subnet "192.168.1." -startIP 1 -endIP 254 -portsToCheck @(80, 443, 22)
