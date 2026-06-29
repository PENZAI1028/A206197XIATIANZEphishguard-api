import { useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle, Info, Shield, XCircle } from 'lucide-react';
import { Badge } from './ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';

const SCORING_CONFIG_API =
  'https://a206197xiatianzephishguard-api.onrender.com/scoring-config';

interface ScoringIndicator {
  name: string;
  label: string;
  method: string;
  scoring_mode: 'weighted' | 'rule_override' | string;
  weight_percent: number;
  used_in_final_score: boolean;
}

interface RiskLevel {
  label: string;
  minimum: number;
  maximum: number;
}

interface ScoringConfig {
  api_version: string;
  score_method: string;
  indicators: ScoringIndicator[];
  indicator_weight_total_percent: number;
  risk_levels: RiskLevel[];
  critical_aggregation: {
    method: string;
    top_signal_weights_percent: number[];
    minimum_critical_score: number;
    maximum_critical_score: number;
  };
}

const riskStyle: Record<string, {
  container: string;
  text: string;
  badge: string;
  icon: typeof CheckCircle;
}> = {
  Trusted: {
    container: 'from-green-50 to-green-100 border-green-500',
    text: 'text-green-800',
    badge: 'bg-green-600 text-white',
    icon: CheckCircle,
  },
  'Low Risk': {
    container: 'from-blue-50 to-blue-100 border-blue-500',
    text: 'text-blue-800',
    badge: 'bg-blue-500 text-white',
    icon: CheckCircle,
  },
  Suspicious: {
    container: 'from-yellow-50 to-yellow-100 border-yellow-500',
    text: 'text-yellow-800',
    badge: 'bg-yellow-500 text-white',
    icon: AlertTriangle,
  },
  'High Risk': {
    container: 'from-red-50 to-red-100 border-red-600',
    text: 'text-red-800',
    badge: 'bg-red-700 text-white',
    icon: XCircle,
  },
};

function displayRiskLabel(level: RiskLevel): string {
  return level.label;
}

function indicatorDescription(indicator: ScoringIndicator): string {
  const descriptions: Record<string, string> = {
    officialDomain: 'Evaluates the parsed hostname against the verified official-domain registry and protected-brand similarity rules.',
    aiModelProbability: 'Combines model probability output with URL lexical evidence.',
    brandVerification: 'Evaluates protected-brand tokens and close domain variants.',
    homographAttack: 'Evaluates Punycode, confusable-character, edit-distance, and hostname-similarity evidence.',
    urlStructure: 'Evaluates URL redirects, @ patterns, IP hosts, top-level domains, encoding, and hostname structure.',
    suspiciousKeywords: 'Evaluates phishing-related terms in the hostname, path, and query.',
    httpsUsage: 'Records the submitted URL scheme as HTTP or HTTPS.',
    urlLengthComplexity: 'Measures URL length and special-character count.',
    reputationEvidence: 'Evaluates bundled historical PhishTank, OpenPhish, and URLHaus reputation evidence.',
  };
  return descriptions[indicator.name] ?? indicator.label;
}

export function ScoringCriteria() {
  const [config, setConfig] = useState<ScoringConfig | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;

    fetch(SCORING_CONFIG_API)
      .then(async response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json() as Promise<ScoringConfig>;
      })
      .then(data => {
        if (!cancelled) setConfig(data);
      })
      .catch(() => {
        if (!cancelled) setError('Scoring configuration refresh required.');
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const weightedIndicators = config?.indicators.filter(
    indicator => indicator.scoring_mode === 'weighted'
      && indicator.used_in_final_score
      && indicator.weight_percent > 0,
  ) ?? [];

  const ruleOverrideIndicators = config?.indicators.filter(
    indicator => indicator.scoring_mode === 'rule_override',
  ) ?? [];

  return (
    <Card className="shadow-lg">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Info className="h-5 w-5 text-indigo-600" />
          Scoring Architecture
        </CardTitle>
        <CardDescription>Live scoring configuration returned by the PhishGuard backend</CardDescription>
      </CardHeader>
      <CardContent className="space-y-8">
        {error && (
          <div className="rounded-lg border border-yellow-300 bg-yellow-50 p-4 text-sm text-yellow-800">
            {error}
          </div>
        )}

        {!config && !error && (
          <div className="rounded-lg border bg-gray-50 p-4 text-sm text-gray-500">
            Loading the active backend scoring configuration.
          </div>
        )}

        {config && (
          <>
            <div className="rounded-lg border border-blue-200 bg-blue-50 p-4 text-sm text-blue-800">
              <p className="mb-1 flex items-center gap-1 font-medium">
                <Shield className="h-4 w-4" />
                Auditable Backend Configuration
              </p>
              <p>{config.score_method}</p>
              <p className="mt-1">
                API version {config.api_version}. Base weighted indicators total{' '}
                {config.indicator_weight_total_percent}%.
              </p>
            </div>

            <div className="rounded-lg border border-green-200 bg-green-50 p-4 text-sm text-green-900">
              <p className="font-semibold">Verified Official Domain Status</p>
              <p className="mt-1">
                The backend displays this status on an individual result after it confirms a hostname match in
                the verified official-domain registry.
              </p>
            </div>

            <div>
              <h3 className="mb-2 text-lg font-semibold">Risk Score Bands</h3>
              <p className="mb-4 text-sm text-gray-500">
                Each label and score range matches the active backend risk-band configuration. Verified Official
                Domain status is a separate registry-match status.
              </p>
              <div className="space-y-3">
                {config.risk_levels.map(level => {
                  const style = riskStyle[level.label] ?? riskStyle['High Risk'];
                  const Icon = style.icon;
                  return (
                    <div
                      key={`${level.label}-${level.minimum}-${level.maximum}`}
                      className={`rounded-lg border-l-4 bg-gradient-to-r p-4 ${style.container}`}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className={`flex items-center gap-2 font-semibold ${style.text}`}>
                          <Icon className="h-5 w-5" />
                          {displayRiskLabel(level)} ({level.minimum}-{level.maximum})
                        </div>
                        <Badge className={style.badge}>{level.minimum}-{level.maximum}</Badge>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div>
              <h3 className="mb-1 text-lg font-semibold">Base Weighted Formula</h3>
              <p className="mb-4 text-sm text-gray-500">
                {weightedIndicators.length} weighted indicators total {config.indicator_weight_total_percent}%.
              </p>
              <div className="space-y-4">
                {weightedIndicators.map(indicator => (
                  <div key={indicator.name} className="rounded-lg border bg-white p-4">
                    <div className="mb-2 flex items-start justify-between gap-3">
                      <h4 className="flex items-center gap-2 font-medium">
                        <span className="h-3 w-3 shrink-0 rounded-full bg-indigo-500" />
                        {indicator.label}
                      </h4>
                      <Badge variant="outline" className="shrink-0 border-indigo-300 text-indigo-700">
                        Weight: {indicator.weight_percent}%
                      </Badge>
                    </div>
                    <p className="text-sm text-gray-600">{indicatorDescription(indicator)}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-lg border border-indigo-200 bg-indigo-50 p-4">
              <h3 className="mb-3 font-semibold text-indigo-900">Live Base Weighted Formula</h3>
              <div className="space-y-1 font-mono text-sm text-indigo-800">
                <p>Base weighted score =</p>
                {weightedIndicators.map((indicator, index) => (
                  <p key={indicator.name} className="ml-4">
                    {index > 0 ? '+ ' : ''}{indicator.label} × {indicator.weight_percent}%
                  </p>
                ))}
                <p className="mt-3 font-sans font-semibold">Final score rule evaluation</p>
                <p className="font-sans">
                  Critical-evidence aggregation combines the highest three active indicator scores.
                </p>
                <p>
                  Critical evidence = highest indicator × {config.critical_aggregation.top_signal_weights_percent[0]}%
                  {' + '}second × {config.critical_aggregation.top_signal_weights_percent[1]}%
                  {' + '}third × {config.critical_aggregation.top_signal_weights_percent[2]}%
                </p>
                <p>
                  Critical risk range = {config.critical_aggregation.minimum_critical_score}-
                  {config.critical_aggregation.maximum_critical_score}
                </p>
                <p className="mt-2">Derived Safety Score = 100 − Final Risk Score</p>
              </div>
            </div>

            <div className="rounded-lg border border-purple-200 bg-purple-50 p-4">
              <h3 className="mb-1 font-semibold text-purple-900">Rule Overrides After the Base Formula</h3>
              <p className="mb-4 text-sm text-purple-800">
                Rule overrides evaluate the final risk score after the 100% base weighted formula.
              </p>
              <div className="space-y-3">
                <div className="rounded border border-purple-200 bg-white p-3">
                  <p className="font-medium text-purple-900">Dynamic Critical-Evidence Aggregation</p>
                  <p className="mt-1 text-sm text-purple-800">
                    The backend aggregates the three highest active indicator scores and records a critical
                    rule trigger in the individual result.
                  </p>
                </div>
                <div className="rounded border border-purple-200 bg-white p-3">
                  <p className="font-medium text-purple-900">Verified Official-Domain Protection</p>
                  <p className="mt-1 text-sm text-purple-800">
                    A verified official registry match receives backend final-score protection and displays
                    Verified Official Domain in the individual result.
                  </p>
                </div>
                {ruleOverrideIndicators.map(indicator => (
                  <div key={indicator.name} className="rounded border border-purple-200 bg-white p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="font-medium text-purple-900">{indicator.label}</p>
                      <Badge variant="outline" className="border-purple-300 text-purple-700">
                        Rule Override · {indicator.weight_percent}% Base Formula Contribution
                      </Badge>
                    </div>
                    <p className="mt-2 text-sm text-purple-800">{indicatorDescription(indicator)}</p>
                    {indicator.name === 'reputationEvidence' && (
                      <p className="mt-2 text-sm text-purple-800">
                        Exact malicious URL and dedicated malicious-host records raise the final risk score.
                        Root-domain historical context is displayed as context evidence.
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4">
              <h3 className="mb-2 font-semibold text-yellow-900">Analysis Evidence Scope</h3>
              <ul className="list-inside list-disc space-y-1 text-sm text-yellow-800">
                <li>URL analysis evaluates submitted URL syntax, model output, verified-domain records, and backend scoring rules.</li>
                <li>HTTPS evaluation records the submitted URL scheme.</li>
                <li>Offline reputation evidence uses bundled PhishTank, OpenPhish, and URLHaus snapshots.</li>
                <li>Each prediction records the base weighted score and the applied backend rule evaluations.</li>
              </ul>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
