/**
 * Adaptive Risk Scoring & Evidence Aggregator for Security Guard
 * Combines Deterministic Rule-Based Signatures with Isolation Forest Anomaly Analysis.
 * 
 * Key Principles:
 * 1. Rule-Based attack signatures have strict precedence.
 * 2. Isolation Forest anomaly scores indicate statistical deviation in request geometry,
 *    NOT attack certainty. An isolated ML anomaly alone never triggers a BLOCK.
 * 3. Evidence fusion calculates a synergistic, non-redundant risk index.
 * 4. In MONITOR_ONLY mode, the decision is strictly capped to ALLOW or MONITOR.
 * 5. Every decision generates a clear audit rationale explaining the evidence chain.
 */

const SEVERITY_BASE_SCORES = {
  'CRITICAL': 90.0,
  'HIGH': 75.0,
  'MEDIUM': 50.0,
  'LOW': 25.0,
  'NONE': 0.0
};

// Thresholds for adaptive decisions
const CONFIG = {
  BLOCK_THRESHOLD: 70.0,
  MONITOR_THRESHOLD: 35.0,
  ML_SYNERGY_WEIGHT: 0.15,
  MAX_STANDALONE_ML_SCORE: 48.0 // Guarantees standalone ML never exceeds BLOCK_THRESHOLD (70)
};

/**
 * Calculates calibrated adaptive risk score and determines final mitigation decision
 * 
 * @param {Object} params
 * @param {Array<Object>} params.ruleDetections - Array of rule hits from Rule-Based Engine
 * @param {Object|null} params.mlResult - Output from Isolation Forest Anomaly Detector
 * @param {string} params.monitoringMode - 'MONITOR_ONLY' or 'ENFORCE'
 * @param {Object|null} params.policyMatch - Matched administrative policy if any
 * @param {number} params.processingTimeMs - Total analysis time
 * @returns {Object} Structured detection evidence and decision result
 */
function evaluateAdaptiveRisk({
  ruleDetections = [],
  mlResult = null,
  monitoringMode = 'MONITOR_ONLY',
  policyMatch = null,
  processingTimeMs = 0.0
}) {
  const currentMode = String(monitoringMode).toUpperCase() === 'ENFORCE' ? 'ENFORCE' : 'MONITOR_ONLY';

  // 1. Evaluate Administrative Policy Override (Priority 1)
  if (policyMatch) {
    if (policyMatch.action === 'ALLOW') {
      return {
        decision: 'ALLOW',
        statusCode: 200,
        riskScore: 0.0,
        ruleSeverity: 'NONE',
        ruleMatches: [],
        mlAnomalyScore: mlResult?.anomaly_score || 0.0,
        mlThreshold: mlResult?.threshold || 0.0,
        mlMode: mlResult?.mode || 'shadow',
        matchedFeatures: [],
        evidence: {
          policyId: policyMatch.id,
          override: 'ADMIN_ALLOW_EXCEPTION',
          reason: policyMatch.reason
        },
        decisionReason: `Explicit Administrative ALLOW Exception #${policyMatch.id}: ${policyMatch.reason}`,
        mode: currentMode,
        processingTimeMs
      };
    }

    if (policyMatch.action === 'BLOCK') {
      const isBlocked = currentMode === 'ENFORCE';
      const reasonText = `Administrative Enforcement Policy #${policyMatch.id} (${policyMatch.policyType}): ${policyMatch.reason}`;
      return {
        decision: isBlocked ? 'BLOCK' : 'MONITOR',
        statusCode: isBlocked ? 403 : 200,
        riskScore: 100.0,
        ruleSeverity: 'CRITICAL',
        ruleMatches: [policyMatch.policyType],
        mlAnomalyScore: mlResult?.anomaly_score || 0.0,
        mlThreshold: mlResult?.threshold || 0.0,
        mlMode: mlResult?.mode || 'shadow',
        matchedFeatures: [],
        evidence: {
          policyId: policyMatch.id,
          policyType: policyMatch.policyType,
          criteria: policyMatch.matchCriteria
        },
        decisionReason: isBlocked ? reasonText : `[MONITOR ONLY] ${reasonText}`,
        mode: currentMode,
        processingTimeMs
      };
    }
  }

  // 2. Evaluate Rule-Based Evidence (Priority 2)
  const activeRuleHits = (ruleDetections || []).filter(d => d.type !== 'ML_ANOMALY');
  let topSeverity = 'NONE';
  let ruleBaseScore = 0.0;
  const ruleNames = [];
  const ruleDetails = [];

  for (const hit of activeRuleHits) {
    const sev = (hit.severity || 'LOW').toUpperCase();
    const hitScore = parseFloat(hit.score) || SEVERITY_BASE_SCORES[sev] || 25.0;
    ruleNames.push(hit.rule_id || hit.type);
    ruleDetails.push({
      ruleId: hit.rule_id || hit.type,
      type: hit.type,
      severity: sev,
      score: hitScore,
      reason: hit.reason
    });

    if (hitScore > ruleBaseScore) {
      ruleBaseScore = hitScore;
      topSeverity = sev;
    }
  }

  // 3. Evaluate Machine Learning Behavioral Anomaly Evidence (Priority 3)
  const isMlAnomaly = Boolean(mlResult?.is_anomaly);
  const mlRawScore = typeof mlResult?.raw_score === 'number' ? mlResult.raw_score : 0.0;
  const mlThreshold = typeof mlResult?.threshold === 'number' ? mlResult.threshold : -0.026;
  const mlConfidence = parseFloat(mlResult?.anomaly_score) || 0.0;
  const mlMode = mlResult?.mode || 'shadow';
  const features = mlResult?.features || {};

  // Identify outlier features (features contributing to anomaly)
  const salientFeatures = [];
  if (isMlAnomaly && features) {
    if (features.url_length > 100) salientFeatures.push(`url_length=${features.url_length}`);
    if (features.query_param_count > 5) salientFeatures.push(`param_count=${features.query_param_count}`);
    if (features.special_char_count > 8) salientFeatures.push(`special_chars=${features.special_char_count}`);
    if (features.char_entropy > 4.0) salientFeatures.push(`entropy=${features.char_entropy.toFixed(2)}`);
  }

  // 4. Adaptive Risk Score Synthesis
  let finalRiskScore = 0.0;
  let reasonComponents = [];

  if (activeRuleHits.length > 0) {
    // Deterministic signature matched: Rule base score + synergistic ML suspicion
    let synergyBonus = 0.0;
    if (isMlAnomaly && mlConfidence > 50.0) {
      synergyBonus = round(mlConfidence * CONFIG.ML_SYNERGY_WEIGHT, 2);
      reasonComponents.push(`Rule ${topSeverity} (${ruleNames.join(', ')}) confirmed with ML behavioral outlier (+${synergyBonus})`);
    } else {
      reasonComponents.push(`Deterministic Rule [${topSeverity}] matched: ${ruleNames.join(', ')}`);
    }
    finalRiskScore = Math.min(100.0, ruleBaseScore + synergyBonus);
  } else if (isMlAnomaly && mlMode !== 'disabled') {
    // Isolated ML anomaly: bounded to prevent uncorroborated blocks
    finalRiskScore = Math.min(CONFIG.MAX_STANDALONE_ML_SCORE, round(mlConfidence * 0.48, 2));
    reasonComponents.push(`Statistical anomaly in request feature space (Decision: ${mlRawScore.toFixed(3)}, Score: ${mlConfidence}) without attack signature`);
  } else {
    // Completely benign
    finalRiskScore = round(Math.max(0.0, (mlConfidence * 0.1)), 2);
    reasonComponents.push('Request conforms to normal traffic distribution; no threat patterns found');
  }

  finalRiskScore = round(finalRiskScore, 2);

  // 5. Decision Resolution
  let decision = 'ALLOW';
  let statusCode = 200;

  if (currentMode === 'ENFORCE') {
    if (finalRiskScore >= CONFIG.BLOCK_THRESHOLD && activeRuleHits.length > 0) {
      // High/Critical attack verified by deterministic rule
      decision = 'BLOCK';
      statusCode = 403;
    } else if (finalRiskScore >= CONFIG.MONITOR_THRESHOLD) {
      decision = 'MONITOR';
      statusCode = 200;
    } else {
      decision = 'ALLOW';
      statusCode = 200;
    }
  } else {
    // MONITOR_ONLY mode: Never blocks; flags as MONITOR if above threshold
    if (finalRiskScore >= CONFIG.MONITOR_THRESHOLD) {
      decision = 'MONITOR';
    } else {
      decision = 'ALLOW';
    }
    statusCode = 200;
  }

  const decisionReason = (currentMode === 'MONITOR_ONLY' && activeRuleHits.length > 0)
    ? `[MONITOR ONLY] ${reasonComponents.join('; ')}`
    : reasonComponents.join('; ');

  // 6. Build Clean Evidence Record (no sensitive data)
  const evidenceRecord = {
    ruleDetections: ruleDetails,
    mlInference: {
      isAnomaly: isMlAnomaly,
      confidence: mlConfidence,
      rawScore: mlRawScore,
      threshold: mlThreshold,
      mode: mlMode,
      salientFeatures
    },
    scoring: {
      ruleBaseScore,
      finalRiskScore,
      thresholds: {
        block: CONFIG.BLOCK_THRESHOLD,
        monitor: CONFIG.MONITOR_THRESHOLD
      }
    }
  };

  return {
    decision,
    statusCode,
    riskScore: finalRiskScore,
    ruleSeverity: topSeverity,
    ruleMatches: ruleNames,
    mlAnomalyScore: mlConfidence,
    mlThreshold,
    mlMode,
    matchedFeatures: salientFeatures,
    evidence: evidenceRecord,
    decisionReason,
    mode: currentMode,
    processingTimeMs
  };
}

function round(val, decimals = 2) {
  const p = Math.pow(10, decimals);
  return Math.round(val * p) / p;
}

module.exports = {
  evaluateAdaptiveRisk,
  SEVERITY_BASE_SCORES,
  CONFIG
};
