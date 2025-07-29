function Find-LiveHosts {
    param(
        [string]$subnet,  # Base IP of the subnet (e.g., 192.168.1.)
        [int]$startIP,    # Starting IP suffix (e.g., 1)
        [int]$endIP       # Ending IP suffix (e.g., 254)
    )
    $liveHosts = @()
    for ($i = $startIP; $i -le $endIP; $i++) {
        $ip = $subnet + $i
        if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
            Write-Host "$ip is live" -ForegroundColor Green
            $liveHosts += $ip
        } else {
            Write-Host "$ip is not live" -ForegroundColor Red
        }
    }
    return $liveHosts
}
# Usage
# Replace '192.168.1.' with your subnet base, and adjust the IP range you want to test.
Find-LiveHosts -subnet "192.168.1." -startIP 1 -endIP 254
