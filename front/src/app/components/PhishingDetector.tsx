import { useState } from 'react';
import {
  Shield, AlertTriangle, CheckCircle, XCircle,
  BarChart3, LogIn, Brain, X, AlertCircle,
  ChevronDown, ChevronUp, Download, Clock, History,
} from 'lucide-react';
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from './ui/card';
import { Input } from './ui/input';
import { Button } from './ui/button';
import { Progress } from './ui/progress';
import { Badge } from './ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer,
} from 'recharts';
import { ScoringCriteria } from './ScoringCriteria';

const PHISHGUARD_API = 'https://a206197xiatianzephishguard-api.onrender.com/predict';
const HISTORY_KEY = 'phishguard_history';

// ─── Types ─────────────────────────────────────────────────────────────────

interface Indicator {
  name: string;
  score?: number;
  risk_points?: number;
  safety_score?: number;
  status?: 'safe' | 'warning' | 'danger' | string;
  explanation?: string;
  value?: unknown;
  used_in_final_score?: boolean;
  weight_percent?: number;
  weighted_contribution_points?: number;
}

interface ScoreAudit {
  indicator_weights: Record<string, number>;
  indicator_weight_total_percent: number;
  weighted_score_before_overrides: number;
  rounded_weighted_score: number;
  final_risk_score: number;
  rounding_adjustment_points: number;
  override_adjustment_points: number;
  applied_overrides: string[];
  critical_evidence_score: number | null;
  critical_top_signals: Array<{
    name: string;
    score: number;
    aggregation_weight_percent: number;
  }>;
}

interface AIResult {
  url: string;
  prediction: 0 | 1;
  decision: string;
  result: string;
  risk_score: number;
  safety_score: number;
  critical_phishing: boolean;
  explanations: string[];
  indicators: Indicator[];
  recommendations: string[];
  score_audit: ScoreAudit;
}

interface HistoryItem {
  url: string;
  result: string;
  decision: string;
  risk_score: number;
  safety_score: number;
  timestamp: string;
}

interface PhishingDetectorProps {
  accessToken?: string;
  onViewDashboard?: () => void;
  onLogin?: () => void;
  onViewAIConfig?: () => void;
}

// ─── Tier config ───────────────────────────────────────────────────────────

type Tier = 'trusted' | 'low-risk' | 'suspicious' | 'high-risk' | 'critical';

function getTier(riskScore: number, criticalPhishing: boolean): Tier {
  if (criticalPhishing || riskScore >= 80) return 'critical';
  if (riskScore >= 60) return 'high-risk';
  if (riskScore >= 40) return 'suspicious';
  if (riskScore >= 20) return 'low-risk';
  return 'trusted';
}

const TIER = {
  trusted: {
    card: 'border-green-500 bg-green-50',
    badgeCls: 'bg-green-600 text-white',
    title: 'text-green-800',
    text: 'text-green-700',
    leftBorder: 'border-l-green-500',
    Icon: CheckCircle,
    iconCls: 'text-green-600',
    heading: 'Trusted — Appears Secure',
    body: 'This URL shows strong safety indicators and no obvious phishing characteristics.',
  },
  'low-risk': {
    card: 'border-blue-500 bg-blue-50',
    badgeCls: 'bg-blue-500 text-white',
    title: 'text-blue-800',
    text: 'text-blue-700',
    leftBorder: 'border-l-blue-500',
    Icon: CheckCircle,
    iconCls: 'text-blue-600',
    heading: 'Low Risk — Relatively Safe',
    body: 'This URL appears relatively safe, but users should still verify the domain.',
  },
  suspicious: {
    card: 'border-yellow-500 bg-yellow-50',
    badgeCls: 'bg-yellow-500 text-white',
    title: 'text-yellow-800',
    text: 'text-yellow-700',
    leftBorder: 'border-l-yellow-500',
    Icon: AlertTriangle,
    iconCls: 'text-yellow-600',
    heading: 'Suspicious — Review Carefully',
    body: 'This URL contains suspicious characteristics and should be reviewed carefully.',
  },
  'high-risk': {
    card: 'border-red-500 bg-red-50',
    badgeCls: 'bg-red-500 text-white',
    title: 'text-red-800',
    text: 'text-red-700',
    leftBorder: 'border-l-red-500',
    Icon: XCircle,
    iconCls: 'text-red-600',
    heading: 'High Risk — Likely Phishing',
    body: 'This URL contains multiple phishing indicators. Avoid entering any sensitive information.',
  },
  critical: {
    card: 'border-red-800 bg-red-100',
    badgeCls: 'bg-red-900 text-white',
    title: 'text-red-900',
    text: 'text-red-800',
    leftBorder: 'border-l-red-800',
    Icon: XCircle,
    iconCls: 'text-red-900',
    heading: 'Critical — Do Not Visit',
    body: 'This URL strongly resembles a phishing or impersonation attack. Do not visit or submit any information.',
  },
} satisfies Record<Tier, object>;

// ─── Indicator name mapping ─────────────────────────────────────────────────

const FRIENDLY_NAMES: Record<string, string> = {
  officialDomain: 'Official Domain Verification',
  aiModelProbability: 'Calibrated AI-Assisted Risk',
  brandVerification: 'Brand Impersonation',
  homographAttack: 'Homograph & Typosquatting',
  urlStructure: 'URL Structure',
  suspiciousKeywords: 'Suspicious Keywords',
  httpsUsage: 'HTTPS Usage',
  urlLengthComplexity: 'URL Length & Complexity',
};

const CHART_LABELS: Record<string, string> = {
  officialDomain: 'Official Domain',
  aiModelProbability: 'AI Model',
  brandVerification: 'Brand Verification',
  homographAttack: 'Homograph Attack',
  urlStructure: 'URL Structure',
  suspiciousKeywords: 'Keywords',
  httpsUsage: 'HTTPS Usage',
  urlLengthComplexity: 'URL Length',
};

function friendlyName(raw: string) {
  return FRIENDLY_NAMES[raw] ?? raw;
}

function chartLabel(raw: string) {
  return CHART_LABELS[raw] ?? raw;
}

// ─── Indicator value renderer (P0 fix: no [object Object]) ─────────────────

function renderIndicatorValue(name: string, value: unknown): React.ReactNode {
  // AI model probability is rendered in its own dedicated block — skip generic value display
  if (name === 'aiModelProbability') return null;

  if (value === null || value === undefined) return <span className="text-gray-400">N/A</span>;

  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-gray-400">N/A</span>;
    return (
      <span className="flex flex-wrap gap-1">
        {value.map((v, i) => (
          <Badge key={i} variant="outline" className="text-xs font-mono">{String(v)}</Badge>
        ))}
      </span>
    );
  }

  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== null && v !== undefined);
    if (entries.length === 0) return <span className="text-gray-400">N/A</span>;
    return (
      <div className="space-y-0.5">
        {entries.map(([k, v]) => {
          const label = k.replace(/_/g, ' ').replace(/([A-Z])/g, ' $1').replace(/^./, s => s.toUpperCase()).trim();
          return (
            <div key={k} className="text-xs">
              <span className="text-gray-500">{label}:</span>{' '}
              <span className="font-mono font-medium">{String(v)}</span>
            </div>
          );
        })}
      </div>
    );
  }

  if (typeof value === 'boolean') {
    return <span className="font-mono">{value ? 'Yes' : 'No'}</span>;
  }

  const str = String(value);
  if (str === '' || str === 'null' || str === 'undefined') {
    return <span className="text-gray-400">N/A</span>;
  }

  return <span className="font-mono text-xs break-all">{str}</span>;
}

// ─── Score colors ──────────────────────────────────────────────────────────

function riskScoreColor(s: number) {
  if (s >= 80) return 'text-red-900';
  if (s >= 60) return 'text-red-600';
  if (s >= 40) return 'text-yellow-600';
  if (s >= 20) return 'text-blue-600';
  return 'text-green-600';
}

function safetyScoreColor(s: number) {
  if (s >= 80) return 'text-green-600';
  if (s >= 60) return 'text-blue-600';
  if (s >= 40) return 'text-yellow-600';
  return 'text-red-600';
}

// ─── localStorage helpers ──────────────────────────────────────────────────

function loadHistory(): HistoryItem[] {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) ?? '[]');
  } catch {
    return [];
  }
}

function pushHistory(item: HistoryItem) {
  const prev = loadHistory();
  const next = [item, ...prev.filter(h => h.url !== item.url || h.timestamp !== item.timestamp)].slice(0, 5);
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
  } catch { /* quota exceeded — ignore */ }
}

// ─── Print helper ──────────────────────────────────────────────────────────

function printReport(result: AIResult, timestamp: string) {
  const win = window.open('', '_blank');
  if (!win) return;
  win.document.write(`
    <html><head><title>PhishGuard Report</title>
    <style>body{font-family:sans-serif;padding:2rem;max-width:800px;margin:auto}h1{color:#3730a3}table{width:100%;border-collapse:collapse;margin:1rem 0}td,th{border:1px solid #ddd;padding:8px;text-align:left}pre{background:#f3f4f6;padding:1rem;overflow-x:auto;font-size:12px}</style>
    </head><body>
    <h1>PhishGuard Analysis Report</h1>
    <table>
      <tr><th>URL</th><td style="word-break:break-all">${result.url}</td></tr>
      <tr><th>Scan Time</th><td>${timestamp}</td></tr>
      <tr><th>Result</th><td>${result.result}</td></tr>
      <tr><th>Decision</th><td>${result.decision}</td></tr>
      <tr><th>Risk Score</th><td>${result.risk_score} / 100</td></tr>
      <tr><th>Safety Score</th><td>${result.safety_score} / 100</td></tr>
      <tr><th>Critical Phishing</th><td>${result.critical_phishing ? 'Yes' : 'No'}</td></tr>
    </table>
    <h2>Explanations</h2>
    <ul>${(result.explanations ?? []).map(e => `<li>${e}</li>`).join('')}</ul>
    <h2>Recommendations</h2>
    <ul>${(result.recommendations ?? []).map(r => `<li>${r}</li>`).join('')}</ul>
    <h2>Indicators</h2>
    <table>
      <tr><th>Indicator</th><th>Status</th><th>Risk Points</th><th>Safety Score</th><th>Explanation</th></tr>
      ${(result.indicators ?? []).filter(
        ind => ind.used_in_final_score === true && FRIENDLY_NAMES[ind.name]
      ).map(ind => `
        <tr>
          <td>${friendlyName(ind.name)}</td>
          <td>${ind.status ?? '—'}</td>
          <td>${ind.risk_points ?? '—'}</td>
          <td>${ind.safety_score ?? '—'}</td>
          <td>${ind.explanation ?? '—'}</td>
        </tr>`).join('')}
    </table>
    <h2>Detection Source</h2>
    <p>PhishGuard AI API — ${PHISHGUARD_API}</p>
    </body></html>`);
  win.document.close();
  win.print();
}

// ─── Component ─────────────────────────────────────────────────────────────

export function PhishingDetector({
  accessToken, onViewDashboard, onLogin, onViewAIConfig,
}: PhishingDetectorProps) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AIResult | null>(null);
  const [scanTime, setScanTime] = useState('');
  const [apiError, setApiError] = useState('');
  const [showRaw, setShowRaw] = useState(false);
  const [history, setHistory] = useState<HistoryItem[]>(loadHistory);

  const handleClear = () => {
    setUrl('');
    setResult(null);
    setApiError('');
    setShowRaw(false);
    setScanTime('');
  };

  const handleAnalyze = async () => {
    const trimmed = url.trim();
    if (!trimmed) return;

    setLoading(true);
    setResult(null);
    setApiError('');
    setShowRaw(false);

    try {
      const response = await fetch(PHISHGUARD_API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed }),
      });

      if (!response.ok) throw new Error(`API responded with ${response.status}`);

      const data: AIResult = await response.json();
      const ts = new Date().toLocaleString();

      setResult(data);
      setScanTime(ts);

      // Save to history
      const histItem: HistoryItem = {
        url: data.url ?? trimmed,
        result: data.result,
        decision: data.decision,
        risk_score: data.risk_score,
        safety_score: data.safety_score,
        timestamp: ts,
      };
      pushHistory(histItem);
      setHistory(loadHistory());

      // Persist to Supabase (best-effort)
      try {
        const { projectId, publicAnonKey } = await import('../../../utils/supabase/info');
        void fetch(
          `https://${projectId}.supabase.co/functions/v1/make-server-358bdfd0/detections`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'apikey': publicAnonKey,
              'Authorization': `Bearer ${accessToken || publicAnonKey}`,
            },
            body: JSON.stringify({
              url: trimmed,
              riskScore: data.risk_score,
              safetyScore: data.safety_score,
              isPhishing: data.prediction === 1,
              result: data.result,
              decision: data.decision,
              critical_phishing: data.critical_phishing,
              explanations: data.explanations,
              recommendations: data.recommendations,
              indicators: data.indicators,
            }),
          }
        ).catch(() => undefined);
      } catch { /* non-fatal */ }
    } catch {
      setApiError('Unable to connect to PhishGuard AI API. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  // ─── Derived ──────────────────────────────────────────────────────────────
  const tier = result ? getTier(result.risk_score, result.critical_phishing) : null;
  const styles = tier ? TIER[tier] : null;

  const participatingIndicators = result?.indicators?.filter(
    ind => ind.used_in_final_score === true
      && Boolean(FRIENDLY_NAMES[ind.name])
      && typeof ind.weight_percent === 'number'
      && ind.weight_percent > 0
  ) ?? [];

  const radarData = participatingIndicators.map(ind => ({
    feature: chartLabel(ind.name),
    score: ind.safety_score ?? 0,
  }));

  const barData = participatingIndicators.map(ind => ({
    name: chartLabel(ind.name),
    'Safety Score': ind.safety_score ?? 0,
  }));

  // ─── Render ───────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-8">
      <div className="max-w-4xl mx-auto">

        {/* Header */}
        <div className="text-center mb-10">
          <div className="flex items-center justify-between mb-6">
            <div className="flex-1" />
            <div className="flex items-center gap-3">
              {onViewAIConfig && (
                <Button
                  onClick={onViewAIConfig}
                  variant="outline"
                  className="gap-2 bg-purple-50 border-purple-300 text-purple-700 hover:bg-purple-100"
                >
                  <Brain className="w-4 h-4" />
                  AI Config
                </Button>
              )}
              {accessToken ? (
                <Button onClick={onViewDashboard} variant="outline" className="gap-2">
                  <BarChart3 className="w-4 h-4" />
                  Admin Dashboard
                </Button>
              ) : (
                onLogin && (
                  <Button onClick={onLogin} variant="outline" className="gap-2">
                    <LogIn className="w-4 h-4" />
                    Administrator Login
                  </Button>
                )
              )}
            </div>
          </div>
          <div className="flex items-center justify-center gap-3 mb-3">
            <Shield className="w-12 h-12 text-indigo-600" />
            <h1 className="text-3xl font-bold text-gray-900">PhishGuard AI Detector</h1>
          </div>
          <p className="text-gray-500 text-sm">
            Powered by a trained machine-learning model — enter any URL for an instant phishing risk assessment
          </p>
        </div>

        {/* ── SECTION 1: URL Input ─────────────────────────────────────────── */}
        <Card className="mb-6 shadow-lg">
          <CardHeader>
            <CardTitle>URL Detection</CardTitle>
            <CardDescription>
              Enter a website URL to analyze with the PhishGuard trained AI model
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-3">
              <Input
                placeholder="e.g., https://www.example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !loading && handleAnalyze()}
                className="flex-1"
                disabled={loading}
              />
              <Button
                onClick={handleAnalyze}
                disabled={loading || !url.trim()}
                className="min-w-[110px]"
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    Scanning
                  </span>
                ) : 'Analyze'}
              </Button>
              {(url || result || apiError) && (
                <Button onClick={handleClear} variant="outline" disabled={loading}>
                  <X className="w-4 h-4" />
                </Button>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Loading */}
        {loading && (
          <Card className="mb-6 border-indigo-200 shadow">
            <CardContent className="pt-6 pb-6">
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 border-4 border-indigo-600 border-t-transparent rounded-full animate-spin shrink-0" />
                <div>
                  <p className="font-semibold text-indigo-800">
                    Analyzing URL with trained PhishGuard AI model...
                  </p>
                  <p className="text-sm text-indigo-500 mt-0.5">This may take a few seconds</p>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* API Error */}
        {apiError && (
          <Card className="mb-6 border-red-300 bg-red-50 shadow">
            <CardContent className="pt-6 pb-6">
              <div className="flex items-center gap-3">
                <AlertCircle className="w-6 h-6 text-red-600 shrink-0" />
                <p className="text-red-700 font-medium">{apiError}</p>
              </div>
            </CardContent>
          </Card>
        )}

        {result && styles && tier && (
          <div className="space-y-5">

            {/* ── SECTION 2: Main Result Banner ──────────────────────────── */}
            <Card className={`shadow-lg border-2 ${styles.card}`}>
              <CardContent className="pt-6 pb-6">
                <div className="flex items-start gap-4">
                  <styles.Icon className={`w-10 h-10 shrink-0 mt-0.5 ${styles.iconCls}`} />
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2 flex-wrap">
                      <h2 className={`text-xl font-bold ${styles.title}`}>{styles.heading}</h2>
                      <Badge className={styles.badgeCls}>{result.result}</Badge>
                      <Badge variant="outline" className="text-gray-600">{result.decision}</Badge>
                      {result.critical_phishing && (
                        <Badge className="bg-red-900 text-white">⚠ Critical Phishing</Badge>
                      )}
                    </div>
                    <p className={`text-sm ${styles.text}`}>{styles.body}</p>
                    <div className="mt-3 space-y-0.5 text-xs text-gray-400">
                      <p className="break-all">Analyzed URL: {result.url}</p>
                      {scanTime && (
                        <p className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          Scan Time: {scanTime}
                        </p>
                      )}
                      <p>Detection Source: PhishGuard AI API</p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* ── SECTION 3: Risk Assessment Results ─────────────────────── */}
            <Card className="shadow">
              <CardHeader>
                <CardTitle>Risk Assessment Results</CardTitle>
                <CardDescription>Scores returned directly by the PhishGuard backend</CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                {/* Scores */}
                <div>
                  <div className="flex justify-between mb-1">
                    <span className="text-sm font-medium text-gray-700">Risk Score</span>
                    <span className={`text-sm font-bold ${riskScoreColor(result.risk_score)}`}>
                      {result.risk_score} / 100
                    </span>
                  </div>
                  <Progress value={result.risk_score} className="h-3" />
                  <p className="text-xs text-gray-400 mt-1">Higher = greater phishing risk</p>
                </div>

                <div>
                  <div className="flex justify-between mb-1">
                    <span className="text-sm font-medium text-gray-700">Safety Score</span>
                    <span className={`text-sm font-bold ${safetyScoreColor(result.safety_score)}`}>
                      {result.safety_score} / 100
                    </span>
                  </div>
                  <Progress value={result.safety_score} className="h-3" />
                  <p className="text-xs text-gray-400 mt-1">Higher = safer website</p>
                </div>

                {/* P0.3: weighted scoring note */}
                <div className="bg-gray-50 border border-gray-200 rounded-md p-3 text-xs text-gray-500">
                  <p>
                    Final risk score is calculated using weighted scoring. Individual indicators may be
                    high-risk, but the final verdict depends on the combined weighted score and critical
                    override rules.
                  </p>
                </div>

                {/* P1.2: weighted scoring explanation card */}
                <details className="group">
                  <summary className="cursor-pointer select-none text-sm font-medium text-indigo-700 hover:text-indigo-900 flex items-center gap-1">
                    <ChevronDown className="w-4 h-4 group-open:hidden" />
                    <ChevronUp className="w-4 h-4 hidden group-open:block" />
                    How this result is calculated
                  </summary>
                  <div className="mt-3 bg-indigo-50 border border-indigo-200 rounded-md p-4 text-xs text-indigo-800 space-y-2">
                    <p className="font-semibold">Backend weighted calculation</p>
                    <ul className="ml-4 space-y-0.5 font-mono">
                      {participatingIndicators.map((ind, index) => (
                        <li key={ind.name}>
                          {index > 0 ? '+ ' : ''}
                          {friendlyName(ind.name)} × {ind.weight_percent}% ={' '}
                          {ind.weighted_contribution_points ?? 0}
                        </li>
                      ))}
                    </ul>
                    <p className="font-mono">
                      Weighted score before overrides = {result.score_audit?.weighted_score_before_overrides}
                    </p>
                    <p className="font-mono">
                      Final risk score = {result.score_audit?.final_risk_score}
                    </p>
                    {result.score_audit?.critical_evidence_score != null && (
                      <>
                        <p className="mt-2 font-semibold">Dynamic critical-evidence calculation:</p>
                        <ul className="ml-4 space-y-0.5 list-disc list-inside">
                          {result.score_audit.critical_top_signals.map(signal => (
                            <li key={signal.name}>
                              {friendlyName(signal.name)}: {signal.score}/100 x{' '}
                              {signal.aggregation_weight_percent}%
                            </li>
                          ))}
                        </ul>
                        <p className="font-mono">
                          Critical evidence score = {result.score_audit.critical_evidence_score}/100
                        </p>
                      </>
                    )}
                    <p className="font-mono">Safety score = 100 - final risk score</p>
                    <p className="font-semibold mt-2">Overrides applied to this scan:</p>
                    {result.score_audit?.applied_overrides?.length > 0 ? (
                      <ul className="ml-4 space-y-0.5 list-disc list-inside">
                        {result.score_audit.applied_overrides.map(rule => (
                          <li key={rule}>{rule}</li>
                        ))}
                      </ul>
                    ) : (
                      <p>No override was applied.</p>
                    )}
                  </div>
                </details>
              </CardContent>
            </Card>

            {/* ── SECTION 4: Detailed Analysis (3 tabs) ──────────────────── */}
            <Card className="shadow-lg">
              <CardHeader>
                <CardTitle>Detailed Analysis Report</CardTitle>
                <CardDescription>Auditable indicators returned by the PhishGuard backend</CardDescription>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="explanation" className="w-full">
                  <TabsList className="grid w-full grid-cols-3">
                    <TabsTrigger value="explanation">Explanation</TabsTrigger>
                    <TabsTrigger value="features">Features</TabsTrigger>
                    <TabsTrigger value="visualization">Visualization</TabsTrigger>
                  </TabsList>

                  {/* TAB 1 — Explanation */}
                  <TabsContent value="explanation" className="space-y-5 mt-5">
                    <div className="bg-gradient-to-r from-indigo-50 to-blue-50 p-5 rounded-lg">
                      <h3 className="font-semibold mb-3 flex items-center gap-2 text-sm">
                        <AlertTriangle className="w-4 h-4 text-indigo-600" />
                        Detection Results Explanation
                      </h3>
                      {result.explanations?.length > 0 ? (
                        <div className="space-y-2">
                          {result.explanations.map((exp, i) => (
                            <div
                              key={i}
                              className={`bg-white p-3 rounded border-l-4 ${styles.leftBorder} text-sm text-gray-700`}
                            >
                              {exp}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm text-gray-500 italic">
                          No obvious phishing indicators were detected.
                        </p>
                      )}
                    </div>
                  </TabsContent>

                  {/* TAB 2 — Features */}
                  <TabsContent value="features" className="mt-5">
                    {participatingIndicators.length > 0 ? (
                      <div className="grid gap-4 md:grid-cols-2">
                        {participatingIndicators.map((ind, i) => {
                          const status = (ind.status ?? '').toLowerCase();
                          const isDanger = status === 'danger';
                          const isWarning = status === 'warning';
                          const isSafe = status === 'safe';
                          const isAI = ind.name === 'aiModelProbability';

                          const borderCls = isDanger
                            ? 'border-red-400' : isWarning
                            ? 'border-yellow-400' : isSafe
                            ? 'border-green-400' : 'border-gray-300';

                          const bgCls = isDanger
                            ? 'bg-red-50' : isWarning
                            ? 'bg-yellow-50' : isSafe
                            ? 'bg-green-50' : 'bg-white';

                          const StatusIcon = isDanger ? XCircle : isWarning ? AlertTriangle : CheckCircle;
                          const iconCls = isDanger
                            ? 'text-red-500' : isWarning
                            ? 'text-yellow-500' : 'text-green-500';

                          const safetyPct = ind.safety_score ?? 0;

                          return (
                            <Card key={i} className={`border-2 ${borderCls} ${bgCls}`}>
                              <CardContent className="pt-4 pb-4">
                                {/* Name + status icon */}
                                <div className="flex items-start justify-between gap-2 mb-2">
                                  <h4 className="font-medium text-sm text-gray-800">
                                    {friendlyName(ind.name)}
                                  </h4>
                                  <StatusIcon className={`w-5 h-5 shrink-0 ${iconCls}`} />
                                </div>

                                {/* Status badge */}
                                {ind.status && (
                                  <Badge
                                    className={`text-xs mb-3 ${
                                      isDanger
                                        ? 'bg-red-100 text-red-700'
                                        : isWarning
                                        ? 'bg-yellow-100 text-yellow-700'
                                        : 'bg-green-100 text-green-700'
                                    }`}
                                  >
                                    {ind.status}
                                  </Badge>
                                )}

                                {/* AI Model Probability — all fields sourced from indicator.value */}
                                {isAI && (() => {
                                  const v = (ind.value && typeof ind.value === 'object')
                                    ? ind.value as Record<string, unknown>
                                    : {};

                                  const fmt = (field: unknown, suffix = '') => {
                                    if (field === undefined || field === null || field === '') {
                                      return <span className="text-gray-400">Not returned by API</span>;
                                    }
                                    return (
                                      <span className="font-mono font-medium">
                                        {typeof field === 'number' ? field.toFixed(2) : String(field)}{suffix}
                                      </span>
                                    );
                                  };

                                  const row = (label: string, content: React.ReactNode) => (
                                    <div className="flex items-start justify-between gap-2 py-1 border-b border-gray-100 last:border-0">
                                      <span className="text-gray-500 shrink-0">{label}</span>
                                      <span className="text-right">{content}</span>
                                    </div>
                                  );

                                  return (
                                    <div className="mb-3 bg-white border border-gray-200 rounded p-3 text-xs text-gray-700 space-y-0">
                                      {row('Effective AI phishing probability',
                                        fmt(v.phishing_probability_percent, '%'))}
                                      {row('Raw model probability',
                                        fmt(v.raw_phishing_probability_percent, '%'))}
                                      {row('Feature-evidence probability',
                                        fmt(v.feature_ai_probability_percent, '%'))}
                                      {row('Calibrated AI-assisted probability',
                                        fmt(v.calibrated_phishing_probability_percent, '%'))}
                                      {row('Adjusted AI risk score',
                                        fmt(v.adjusted_ai_risk_score !== undefined
                                          ? `${v.adjusted_ai_risk_score} / 100`
                                          : undefined))}
                                      {row('Backend weight',
                                        fmt(v.weight_percent, '%'))}
                                      {row('Final weighted contribution',
                                        fmt(v.weighted_contribution_points !== undefined
                                          ? `${v.weighted_contribution_points} / 100`
                                          : undefined))}
                                    </div>
                                  );
                                })()}

                                {/* Risk points */}
                                {ind.risk_points !== undefined && (
                                  <p className="text-xs text-gray-500 mb-1">
                                    Risk Points:{' '}
                                    <span className="font-medium text-gray-700">{ind.risk_points} / 100</span>
                                  </p>
                                )}

                                {/* Safety score bar */}
                                {ind.safety_score !== undefined && (
                                  <div className="mt-2 mb-3">
                                    <div className="flex justify-between text-xs mb-1">
                                      <span className="text-gray-500">Safety Score</span>
                                      <span className="font-medium">{safetyPct}</span>
                                    </div>
                                    <Progress value={safetyPct} className="h-1.5" />
                                  </div>
                                )}

                                {/* Explanation */}
                                {ind.explanation && (
                                  <p className="text-xs text-gray-600 mt-2 leading-relaxed">
                                    {ind.explanation}
                                  </p>
                                )}

                                {/* Value — skip for aiModelProbability (rendered above) */}
                                {!isAI && ind.value !== undefined && ind.value !== null && (
                                  <div className="mt-3 pt-2 border-t border-gray-100">
                                    <p className="text-xs text-gray-400 mb-1">Value</p>
                                    <div className="text-xs text-gray-700">
                                      {renderIndicatorValue(ind.name, ind.value)}
                                    </div>
                                  </div>
                                )}
                              </CardContent>
                            </Card>
                          );
                        })}
                      </div>
                    ) : (
                      <p className="text-sm text-gray-400 text-center py-8">
                        No indicator data returned by the API.
                      </p>
                    )}
                  </TabsContent>

                  {/* TAB 3 — Visualization */}
                  <TabsContent value="visualization" className="mt-5 space-y-8">
                    {radarData.length > 0 ? (
                      <>
                        {/* Radar */}
                        <div>
                          <h3 className="font-medium mb-1">Security Indicator Safety Levels</h3>
                          <p className="text-xs text-gray-400 mb-4">Higher values mean safer indicators.</p>
                          <ResponsiveContainer width="100%" height={380}>
                            <RadarChart data={radarData}>
                              <PolarGrid />
                              <PolarAngleAxis dataKey="feature" tick={{ fontSize: 11 }} />
                              <PolarRadiusAxis angle={90} domain={[0, 100]} tick={{ fontSize: 10 }} />
                              <Radar
                                name="Safety Score"
                                dataKey="score"
                                stroke="#4f46e5"
                                fill="#4f46e5"
                                fillOpacity={0.55}
                              />
                              <Tooltip />
                            </RadarChart>
                          </ResponsiveContainer>
                        </div>

                        {/* Bar */}
                        <div>
                          <h3 className="font-medium mb-1">Indicator Safety Scores</h3>
                          <p className="text-xs text-gray-400 mb-4">Higher values mean safer indicators.</p>
                          <ResponsiveContainer width="100%" height={300}>
                            <BarChart data={barData}>
                              <CartesianGrid strokeDasharray="3 3" />
                              <XAxis dataKey="name" tick={{ fontSize: 10 }} />
                              <YAxis domain={[0, 100]} />
                              <Tooltip />
                              <Legend />
                              <Bar dataKey="Safety Score" fill="#4f46e5" />
                            </BarChart>
                          </ResponsiveContainer>
                        </div>
                      </>
                    ) : (
                      <p className="text-sm text-gray-400 text-center py-8">
                        No indicator data available for visualization.
                      </p>
                    )}
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>

            {/* ── SECTION 5: Recommendations ─────────────────────────────── */}
            {result.recommendations?.length > 0 && (
              <Card className="shadow">
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-indigo-500" />
                    Security Recommendations
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2">
                    {result.recommendations.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-gray-700">
                        <span className="text-indigo-500 mt-0.5 shrink-0">•</span>
                        {rec}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}

            {/* ── SECTION 6: Admin / Debug ────────────────────────────────── */}
            <Card className="shadow border-gray-200">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base flex items-center gap-2">
                    <History className="w-4 h-4 text-gray-500" />
                    Recent Scan History
                  </CardTitle>
                  {/* P2: Export Report */}
                  <Button
                    variant="outline"
                    size="sm"
                    className="gap-2 text-xs"
                    onClick={() => printReport(result, scanTime)}
                  >
                    <Download className="w-3 h-3" />
                    Export Report
                  </Button>
                </div>
                <CardDescription>Last 5 scans stored locally in this browser</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* History table */}
                {history.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-gray-500 border-b">
                          <th className="text-left py-2 pr-3 font-medium">Time</th>
                          <th className="text-left py-2 pr-3 font-medium">URL</th>
                          <th className="text-left py-2 pr-3 font-medium">Result</th>
                          <th className="text-left py-2 pr-3 font-medium">Risk</th>
                          <th className="text-left py-2 font-medium">Decision</th>
                        </tr>
                      </thead>
                      <tbody>
                        {history.map((h, i) => (
                          <tr key={i} className="border-b border-gray-50 hover:bg-gray-50">
                            <td className="py-2 pr-3 whitespace-nowrap text-gray-400">{h.timestamp}</td>
                            <td className="py-2 pr-3 max-w-[180px] truncate font-mono text-gray-700"
                              title={h.url}>{h.url}</td>
                            <td className="py-2 pr-3">
                              <Badge className={`text-xs ${
                                h.risk_score >= 80 ? 'bg-red-900 text-white' :
                                h.risk_score >= 60 ? 'bg-red-500 text-white' :
                                h.risk_score >= 40 ? 'bg-yellow-500 text-white' :
                                h.risk_score >= 20 ? 'bg-blue-500 text-white' :
                                'bg-green-600 text-white'
                              }`}>{h.result}</Badge>
                            </td>
                            <td className="py-2 pr-3 font-mono">{h.risk_score}</td>
                            <td className="py-2 text-gray-600">{h.decision}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-xs text-gray-400">No scan history yet.</p>
                )}

                {/* P1.3: Raw API Response collapsible */}
                <div className="border-t pt-4">
                  <button
                    className="flex items-center gap-2 text-xs text-gray-500 hover:text-gray-700 select-none"
                    onClick={() => setShowRaw(v => !v)}
                  >
                    {showRaw
                      ? <ChevronUp className="w-3 h-3" />
                      : <ChevronDown className="w-3 h-3" />}
                    {showRaw ? 'Hide' : 'Show'} Raw API Response
                  </button>
                  {showRaw && (
                    <pre className="mt-3 bg-gray-900 text-green-400 text-xs p-4 rounded-lg overflow-x-auto max-h-96 leading-relaxed">
                      {JSON.stringify(result, null, 2)}
                    </pre>
                  )}
                </div>
              </CardContent>
            </Card>

          </div>
        )}

        {/* ── Empty state ─────────────────────────────────────────────────── */}
        {!result && !loading && !apiError && (
          <>
            <Card className="shadow mb-6">
              <CardHeader>
                <CardTitle>Test Examples</CardTitle>
                <CardDescription>Click a URL to load it into the analyzer</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-2 sm:grid-cols-2">
                  <Button
                    variant="outline"
                    onClick={() => setUrl('https://www.google.com')}
                    className="justify-start text-sm"
                  >
                    ✅ Safe — https://www.google.com
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => setUrl('https://www.goog1e.com')}
                    className="justify-start text-sm"
                  >
                    🚫 Homograph — goog1e.com
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => setUrl('http://paypal-login-security.com')}
                    className="justify-start text-sm"
                  >
                    🚫 Phishing — paypal-login-security.com
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => setUrl('http://192.168.1.10/login')}
                    className="justify-start text-sm"
                  >
                    🚫 IP URL — http://192.168.1.10/login
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Recent history even on empty state */}
            {history.length > 0 && (
              <Card className="shadow mb-6">
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <History className="w-4 h-4 text-gray-500" />
                    Recent Scans
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="text-gray-500 border-b">
                          <th className="text-left py-2 pr-3 font-medium">Time</th>
                          <th className="text-left py-2 pr-3 font-medium">URL</th>
                          <th className="text-left py-2 pr-3 font-medium">Result</th>
                          <th className="text-left py-2 pr-3 font-medium">Risk</th>
                          <th className="text-left py-2 font-medium">Decision</th>
                        </tr>
                      </thead>
                      <tbody>
                        {history.map((h, i) => (
                          <tr
                            key={i}
                            className="border-b border-gray-50 hover:bg-gray-50 cursor-pointer"
                            onClick={() => setUrl(h.url)}
                          >
                            <td className="py-2 pr-3 whitespace-nowrap text-gray-400">{h.timestamp}</td>
                            <td className="py-2 pr-3 max-w-[180px] truncate font-mono text-gray-700"
                              title={h.url}>{h.url}</td>
                            <td className="py-2 pr-3">
                              <Badge className={`text-xs ${
                                h.risk_score >= 80 ? 'bg-red-900 text-white' :
                                h.risk_score >= 60 ? 'bg-red-500 text-white' :
                                h.risk_score >= 40 ? 'bg-yellow-500 text-white' :
                                h.risk_score >= 20 ? 'bg-blue-500 text-white' :
                                'bg-green-600 text-white'
                              }`}>{h.result}</Badge>
                            </td>
                            <td className="py-2 pr-3 font-mono">{h.risk_score}</td>
                            <td className="py-2 text-gray-600">{h.decision}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            )}

            <ScoringCriteria />
          </>
        )}
      </div>
    </div>
  );
}
