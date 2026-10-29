/**
 * Live Attack Demo Runner for SECURITY GUARD
 */

const http = require('http');

function sendRequest(options, postData = null) {
  return new Promise((resolve) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve({ statusCode: res.statusCode, data }));
    });
    req.on('error', (err) => resolve({ error: err.message }));
    if (postData) req.write(postData);
    req.end();
  });
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function runDemo() {
  console.log('=======================================================');
  console.log('   SECURITY GUARD - LIVE ATTACK DETECTION DEMO         ');
  console.log('   Phát hiện bất thường & Quản lý cảnh báo thời gian thực');
  console.log('=======================================================\n');

  // 1. SQL Injection
  console.log('\x1b[33m[1/5] Demo 1: Tấn công SQL Injection (SQLi)\x1b[0m');
  console.log("  -> Gửi request: GET /search?q=' OR 1=1--");
  const res1 = await sendRequest({
    hostname: 'localhost',
    port: 3000,
    path: "/search?q=%27%20OR%201=1--",
    method: 'GET'
  });
  console.log(`  -> Web App phản hồi: HTTP ${res1.statusCode}\n`);
  await sleep(1000);

  // 2. XSS
  console.log('\x1b[33m[2/5] Demo 2: Tấn công Cross-Site Scripting (XSS)\x1b[0m');
  console.log("  -> Gửi request: GET /search?q=<script>alert('Pwned')</script>");
  const res2 = await sendRequest({
    hostname: 'localhost',
    port: 3000,
    path: "/search?q=%3Cscript%3Ealert(%27Pwned%27)%3C/script%3E",
    method: 'GET'
  });
  console.log(`  -> Web App phản hồi: HTTP ${res2.statusCode}\n`);
  await sleep(1000);

  // 3. Suspicious URL Probing
  console.log('\x1b[33m[3/5] Demo 3: Dò quét tệp nhạy cảm (Suspicious URL Probing)\x1b[0m');
  console.log("  -> Gửi request: GET /.env");
  const res3 = await sendRequest({
    hostname: 'localhost',
    port: 3000,
    path: "/.env",
    method: 'GET'
  });
  console.log(`  -> Web App phản hồi: HTTP ${res3.statusCode}\n`);
  await sleep(1000);

  // 4. Scanner Signature
  console.log('\x1b[33m[4/5] Demo 4: Rà quét bằng công cụ tự động (Security Scanner: sqlmap)\x1b[0m');
  console.log("  -> Gửi request: GET /search?q=test với User-Agent: sqlmap/1.6#stable");
  const res4 = await sendRequest({
    hostname: 'localhost',
    port: 3000,
    path: "/search?q=test",
    method: 'GET',
    headers: { 'User-Agent': 'sqlmap/1.6#stable' }
  });
  console.log(`  -> Web App phản hồi: HTTP ${res4.statusCode}\n`);
  await sleep(1000);

  // 5. Brute Force
  console.log('\x1b[33m[5/5] Demo 5: Tấn công dò mật khẩu (Brute Force: 5 lần sai mật khẩu)\x1b[0m');
  for (let i = 1; i <= 5; i++) {
    const postBody = JSON.stringify({ username: 'admin', password: `wrong_pass_${i}` });
    const resBf = await sendRequest({
      hostname: 'localhost',
      port: 3000,
      path: '/login',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postBody)
      }
    }, postBody);
    console.log(`  -> Lần ${i}: POST /login [admin] -> HTTP ${resBf.statusCode}`);
    await sleep(250);
  }

  console.log('\n\x1b[36mDang đợi Detection Engine xử lý và ghi nhận cảnh báo...\x1b[0m');
  await sleep(2000);

  // Fetch Latest Alerts
  console.log('\n=======================================================');
  console.log('   KẾT QUẢ CẢNH BÁO MỚI NHẤT TRÊN HỆ THỐNG (TOP 5)   ');
  console.log('=======================================================');

  const alertsRes = await sendRequest({
    hostname: 'localhost',
    port: 3000,
    path: '/api/alerts?limit=5&sort=newest',
    method: 'GET'
  });

  if (alertsRes.data) {
    try {
      const parsed = JSON.parse(alertsRes.data);
      if (parsed.alerts && parsed.alerts.length > 0) {
        parsed.alerts.forEach((alert) => {
          const sevColor = alert.severity === 'CRITICAL' || alert.severity === 'HIGH' ? '\x1b[31m' : '\x1b[33m';
          console.log(`\n• Alert #${alert.id}: ${sevColor}[${alert.severity}]\x1b[0m ${alert.alertType} - Risk: ${alert.riskScore}/100`);
          console.log(`  - Mục tiêu: ${alert.method} ${alert.targetUrl}`);
          console.log(`  - IP: ${alert.sourceIp} | Trạng thái: \x1b[32m${(alert.status || 'NEW').toUpperCase()}\x1b[0m`);
          console.log(`  - Lý do: ${alert.description}`);
          console.log(`  - Thời gian: ${new Date(alert.createdAt || alert.timestamp).toLocaleString()}`);
        });
      }
    } catch (e) {
      console.log('Error parsing alerts response:', e.message);
    }
  }

  console.log('\n\x1b[32m=======================================================');
  console.log('  DEMO HOÀN TẤT!');
  console.log('  -> Dashboard: http://localhost:5173');
  console.log('  -> Web App:   http://localhost:3000');
  console.log('  -> Engine:    http://localhost:5000/docs');
  console.log('=======================================================\x1b[0m\n');
}

runDemo();
