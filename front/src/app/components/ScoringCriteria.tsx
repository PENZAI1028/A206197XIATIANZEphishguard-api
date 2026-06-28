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
  limitations: string[];
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
        if (cancelled) return;
        const activeIndicators = data.indicators.filter(
          indicator => indicator.used_in_final_score && indicator.weight_percent > 0
        );
        setConfig({ ...data, indicators: activeIndicators });
      })
      .catch(() => {
        if (!cancelled) {
          setError('The live backend scoring configuration is unavailable. No estimated criteria are shown.');
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <Card className="shadow-lg">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Info className="w-5 h-5 text-indigo-600" />
          Scoring Criteria & Risk Levels
        </CardTitle>
        <CardDescription>
          Live scoring configuration returned by the PhishGuard backend
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-8">
        {error && (
          <div className="rounded-lg border border-yellow-300 bg-yellow-50 p-4 text-sm text-yellow-800">
            {error}
          </div>
        )}

        {!config && !error && (
          <div className="rounded-lg border bg-gray-50 p-4 text-sm text-gray-500">
            Loading the active backend scoring configuration...
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
                API version {config.api_version}. Active weights total{' '}
                {config.indicator_weight_total_percent}%.
              </p>
            </div>

            <div>
              <h3 className="mb-4 text-lg font-semibold">Overall Risk Levels</h3>
              <div className="space-y-3">
                {config.risk_levels.map(level => {
                  const style = riskStyle[level.label] ?? riskStyle['High Risk'];
                  const Icon = style.icon;
                  return (
                    <div
                      key={level.label}
                      className={`rounded-lg border-l-4 bg-gradient-to-r p-4 ${style.container}`}
                    >
                      <div className="flex items-center justify-between">
                        <div className={`flex items-center gap-2 font-semibold ${style.text}`}>
                          <Icon className="h-5 w-5" />
                          {level.label} ({level.minimum}-{level.maximum})
                        </div>
                        <Badge className={style.badge}>{level.label}</Badge>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div>
              <h3 className="mb-4 text-lg font-semibold">Active Scoring Indicators</h3>
              <div className="space-y-4">
                {config.indicators.map(indicator => (
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
                    <p className="text-sm text-gray-600">{indicator.method}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-lg border border-indigo-200 bg-indigo-50 p-4">
              <h3 className="mb-3 font-semibold text-indigo-900">Live Weighted Formula</h3>
              <div className="space-y-1 font-mono text-sm text-indigo-800">
                <p>Final weighted score before overrides =</p>
                {config.indicators.map((indicator, index) => (
                  <p key={indicator.name} className="ml-4">
                    {index > 0 ? '+ ' : ''}
                    {indicator.label} x {indicator.weight_percent}%
                  </p>
                ))}
                <p className="mt-3">{config.critical_aggregation.method}</p>
                <p>
                  Critical evidence = highest indicator x{' '}
                  {config.critical_aggregation.top_signal_weights_percent[0]}% + second x{' '}
                  {config.critical_aggregation.top_signal_weights_percent[1]}% + third x{' '}
                  {config.critical_aggregation.top_signal_weights_percent[2]}%
                </p>
                <p>
                  Critical range = {config.critical_aggregation.minimum_critical_score}-
                  {config.critical_aggregation.maximum_critical_score}
                </p>
                <p className="mt-2">Safety score = 100 - final risk score</p>
              </div>
            </div>

            <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4">
              <h3 className="mb-2 font-semibold text-yellow-900">Verified Limitations</h3>
              <ul className="list-inside list-disc space-y-1 text-sm text-yellow-800">
                {config.limitations.map(limitation => (
                  <li key={limitation}>{limitation}</li>
                ))}
              </ul>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
