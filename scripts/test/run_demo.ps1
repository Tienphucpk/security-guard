# SECURITY GUARD - Automated Demo Script
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "   SECURITY GUARD - LIVE ATTACK DETECTION DEMO         " -ForegroundColor Cyan
Write-Host "   Phát hiện bất thường & Quản lý cảnh báo thời gian thực" -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host ""

$baseWeb = "http://localhost:3000"

# 1. SQL Injection Demo
Write-Host "[1/5] Demo 1: Tấn công SQL Injection (SQLi)" -ForegroundColor Yellow
$sqliUrl = "$baseWeb/search?q=%27%20OR%201=1--"
Write-Host "  -> Gửi request: GET $sqliUrl"
try {
    $res1 = Invoke-WebRequest -Uri $sqliUrl -UseBasicParsing -TimeoutSec 5
    Write-Host "  -> Web App phản hồi: HTTP $($res1.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "  -> Web App phản hồi: $($_.Exception.Message)"
}
Start-Sleep -Milliseconds 800

# 2. XSS Demo
Write-Host ""
Write-Host "[2/5] Demo 2: Tấn công Cross-Site Scripting (XSS)" -ForegroundColor Yellow
$xssUrl = "$baseWeb/search?q=%3Cscript%3Ealert(%27Pwned%27)%3C/script%3E"
Write-Host "  -> Gửi request: GET $xssUrl"
try {
    $res2 = Invoke-WebRequest -Uri $xssUrl -UseBasicParsing -TimeoutSec 5
    Write-Host "  -> Web App phản hồi: HTTP $($res2.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "  -> Web App phản hồi: $($_.Exception.Message)"
}
Start-Sleep -Milliseconds 800

# 3. Suspicious URL Probing Demo
Write-Host ""
Write-Host "[3/5] Demo 3: Dò quét tệp nhạy cảm (Suspicious URL Probing)" -ForegroundColor Yellow
$probeUrl = "$baseWeb/.env"
Write-Host "  -> Gửi request: GET $probeUrl"
try {
    $res3 = Invoke-WebRequest -Uri $probeUrl -UseBasicParsing -TimeoutSec 5
    Write-Host "  -> Web App phản hồi: HTTP $($res3.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "  -> Web App phản hồi: $($_.Exception.Message)"
}
Start-Sleep -Milliseconds 800

# 4. Scanner Tool Signature Demo
Write-Host ""
Write-Host "[4/5] Demo 4: Rà quét bằng công cụ tự động (Security Scanner Tool)" -ForegroundColor Yellow
$scannerUrl = "$baseWeb/search?q=test"
$scannerUa = "sqlmap/1.6#stable"
Write-Host "  -> Gửi request: GET $scannerUrl (User-Agent: $scannerUa)"
try {
    $res4 = Invoke-WebRequest -Uri $scannerUrl -UserAgent $scannerUa -UseBasicParsing -TimeoutSec 5
    Write-Host "  -> Web App phản hồi: HTTP $($res4.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "  -> Web App phản hồi: $($_.Exception.Message)"
}
Start-Sleep -Milliseconds 800

# 5. Brute Force Login Demo
Write-Host ""
Write-Host "[5/5] Demo 5: Tấn công dò mật khẩu (Brute Force Login: 5 lần thất bại)" -ForegroundColor Yellow
for ($i = 1; $i -le 5; $i++) {
    Write-Host "  -> Lần $i: POST $baseWeb/login (sai mật khẩu)"
    try {
        $body = @{ username = "admin"; password = "wrong_password_$i" } | ConvertTo-Json
        $res5 = Invoke-WebRequest -Uri "$baseWeb/login" -Method POST -Body $body -ContentType "application/json" -UseBasicParsing -TimeoutSec 5
    } catch {
        # 401 Unauthorized is expected
    }
    Start-Sleep -Milliseconds 200
}

Start-Sleep -Seconds 2

# Fetch Latest Security Alerts
Write-Host ""
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "   KẾT QUẢ CẢNH BÁO MỚI NHẤT TRÊN HỆ THỐNG             " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

try {
    $alertsData = Invoke-RestMethod -Uri "$baseWeb/api/alerts?limit=5&sort=newest"
    $alerts = $alertsData.alerts
    foreach ($a in $alerts) {
        Write-Host "• Alert #$($a.id): [$($a.severity)] $($a.alertType) - Risk: $($a.riskScore)/100" -ForegroundColor Red
        Write-Host "  - Target: $($a.method) $($a.targetUrl)"
        Write-Host "  - IP: $($a.sourceIp) | Trạng thái: $($a.status.ToUpper())"
        Write-Host "  - Lý do: $($a.description)"
        Write-Host ""
    }
} catch {
    Write-Host "Lỗi khi lấy danh sách cảnh báo: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "-> Mời bạn mở Dashboard tại: http://localhost:5173 để xem giao diện quản lý cảnh báo trực tiếp!" -ForegroundColor Green
