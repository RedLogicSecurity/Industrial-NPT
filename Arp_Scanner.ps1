function Get-ARPList {
    param(
        [string]$subnet,
        [int]$startIP,
        [int]$endIP
    )
    $arpList = @()

    # Send a dummy request to populate the ARP table
    for ($i = $startIP; $i -le $endIP; $i++) {
        $ip = "$subnet$i"
        Test-NetConnection -ComputerName $ip -CommonTCPPort HTTP -WarningAction SilentlyContinue | Out-Null
    }
    # Check the ARP table
    $arpEntries = arp -a | Where-Object { $_ -like "*$subnet*" }
    foreach ($entry in $arpEntries) {
        if ($entry -match "(\d+\.\d+\.\d+\.\d+)") {
            $ip = $matches[1]
            if ($ip) {
                Write-Host "$ip is live" -ForegroundColor Green
                $arpList += $ip
            }
        }
    }
    return $arpList
}
# Usage
Get-ARPList -subnet "192.168.1." -startIP 1 -endIP 254
