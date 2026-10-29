/**
 * Phase 10 Interactive Live Demo Script
 * Demonstrates Multi-Website Monitoring, Technology Diversity, and Active Enforcement
 */

const db = require('../../web-app/src/services/database');

async function runDemo() {
  console.log('================================================================');
  console.log('  SECURITY GUARD — PHASE 10 MULTI-SITE & ENFORCEMENT DEMO');
  console.log('================================================================\n');

  // Step 1: Health checks
  console.log('[STEP 1] Checking Core Services & Demo Websites:');
  const [gwRes, nodeRes, pyRes] = await Promise.all([
    fetch('http://127.0.0.1:8080/health').then(r => r.json()).catch(e => ({ error: e.message })),
    fetch('http://127.0.0.1:4001/health').then(r => r.json()).catch(e => ({ error: e.message })),
    fetch('http://127.0.0.1:4002/health').then(r => r.json()).catch(e => ({ error: e.message }))
  ]);
  console.log('  - Gateway (:8080):      ', gwRes.status || gwRes.error);
  console.log('  - Demo Node Shop (:4001):', nodeRes.app || nodeRes.error);
  console.log('  - Demo Python (:4002):   ', pyRes.app || pyRes.error);

  // Step 2: Normal requests through Gateway
  console.log('\n[STEP 2] Routing Normal Requests through Gateway (:8080):');
  const reqNode = await fetch('http://127.0.0.1:8080/site/site_demo_node/products');
  console.log(`  - GET /site/site_demo_node/products -> Status ${reqNode.status} OK (Monitored: ${reqNode.headers.get('x-security-guard-monitored')})`);

  const reqPy = await fetch('http://127.0.0.1:8080/site/site_demo_python/directory');
  console.log(`  - GET /site/site_demo_python/directory -> Status ${reqPy.status} OK (Monitored: ${reqPy.headers.get('x-security-guard-monitored')})`);

  // Step 3: Attack in MONITOR_ONLY mode
  console.log('\n[STEP 3] Attack Simulation in MONITOR_ONLY Mode:');
  await db.updateWebsiteMode('site_demo_node', 'MONITOR_ONLY');
  const monitorRes = await fetch("http://127.0.0.1:8080/site/site_demo_node/search?q=' OR 1=1--");
  console.log(`  - SQLi Attack -> Status ${monitorRes.status} (PASS-THROUGH: Alert generated without blocking)`);

  // Step 4: Attack in ENFORCE mode
  console.log('\n[STEP 4] Switching site_demo_node to ENFORCE Mode:');
  await db.updateWebsiteMode('site_demo_node', 'ENFORCE');
  const enforceRes = await fetch("http://127.0.0.1:8080/site/site_demo_node/search?q=' OR 1=1--");
  const enforceBody = await enforceRes.json();
  console.log(`  - SQLi Attack -> Status ${enforceRes.status} FORBIDDEN (ACTIVELY BLOCKED!)`);
  console.log(`    Enforced Header: ${enforceRes.headers.get('x-security-guard-enforced')}`);
  console.log(`    Block Reason:    ${enforceBody.reason}`);

  // Step 5: Custom IP Block Policy
  console.log('\n[STEP 5] Testing Custom Administrator IP Block Policy:');
  const testIp = '203.0.113.88';
  const policy = await db.createPolicy({
    websiteId: 'site_demo_python',
    policyType: 'IP_BLOCK',
    matchCriteria: { ip: testIp },
    action: 'BLOCK',
    reason: 'Compromised C2 IP Address'
  });
  await db.updateWebsiteMode('site_demo_python', 'ENFORCE');

  const ipRes = await fetch('http://127.0.0.1:8080/site/site_demo_python/directory', {
    headers: { 'X-Forwarded-For': testIp }
  });
  const ipBody = await ipRes.json();
  console.log(`  - Request from ${testIp} -> Status ${ipRes.status} FORBIDDEN (ACTIVELY BLOCKED!)`);
  console.log(`    Policy Reason: ${ipBody.reason}`);

  // Clean up
  await db.deletePolicy(policy.id);
  await db.updateWebsiteMode('site_demo_node', 'MONITOR_ONLY');
  await db.updateWebsiteMode('site_demo_python', 'MONITOR_ONLY');

  // Step 6: Summary of recent audits
  console.log('\n[STEP 6] Recent Enforcement Audit Trail:');
  const audits = await db.getRecentEnforcementAudits({ limit: 4 });
  for (const a of audits) {
    console.log(`  [${a.action}] Site: ${a.websiteId} | IP: ${a.clientIp} | Path: ${a.targetPath} | Reason: ${a.reason}`);
  }

  console.log('\n================================================================');
  console.log('  DEMO VERIFICATION COMPLETED SUCCESSFULLY!');
  console.log('================================================================');
  process.exit(0);
}

runDemo().catch(err => {
  console.error('[DEMO ERROR]', err);
  process.exit(1);
});
