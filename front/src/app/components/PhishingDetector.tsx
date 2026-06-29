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
  used_as_reputation_override?: boolean;
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
  critical_phishing?: boolean;
  verified_official?: boolean;
}

interface PhishingDetectorProps {
  accessToken?: string;
  onViewDashboard?: () => void;
  onLogin?: () => void;
  onViewAIConfig?: () => void;
}

// ─── Tier config ───────────────────────────────────────────────────────────

type Tier = 'verified-official' | 'low-risk' | 'suspicious' | 'high-risk';

function isVerifiedOfficialDomain(result: AIResult): boolean {
  const indicator = result.indicators?.find(item => item.name === 'officialDomain');
  if (!indicator || indicator.status !== 'safe' || typeof indicator.value !== 'object' || !indicator.value) {
    return false;
  }

  const value = indicator.value as Record<string, unknown>;
  return typeof value.matched_domain === 'string' && value.matched_domain.length > 0;
}

function getTier(riskScore: number, verifiedOfficial: boolean): Tier {
  if (riskScore >= 80) return 'high-risk';
  if (riskScore >= 45) return 'suspicious';
  if (verifiedOfficial && riskScore <= 19) return 'verified-official';
  return 'low-risk';
}

const TIER = {
  'verified-official': {
    card: 'border-green-500 bg-green-50',
    badgeCls: 'bg-green-600 text-white',
    title: 'text-green-800',
    text: 'text-green-700',
    leftBorder: 'border-l-green-500',
    Icon: CheckCircle,
    iconCls: 'text-green-600',
    heading: 'Verified Official Domain',
    body: 'This URL matches the verified official-domain registry.',
  },
  'low-risk': {
    card: 'border-blue-500 bg-blue-50',
    badgeCls: 'bg-blue-500 text-white',
    title: 'text-blue-800',
    text: 'text-blue-700',
    leftBorder: 'border-l-blue-500',
    Icon: CheckCircle,
    iconCls: 'text-blue-600',
    heading: 'Low Risk Score',
    body: 'The active scoring engine produced a low risk score for this URL.',
  },
  suspicious: {
    card: 'border-yellow-500 bg-yellow-50',
    badgeCls: 'bg-yellow-500 text-white',
    title: 'text-yellow-800',
    text: 'text-yellow-700',
    leftBorder: 'border-l-yellow-500',
    Icon: AlertTriangle,
    iconCls: 'text-yellow-600',
    heading: 'Suspicious Risk Evidence Detected',
    body: 'This URL triggered elevated-risk indicators in the active analysis.',
  },
  'high-risk': {
    card: 'border-red-500 bg-red-50',
    badgeCls: 'bg-red-500 text-white',
    title: 'text-red-800',
    text: 'text-red-700',
    leftBorder: 'border-l-red-500',
    Icon: XCircle,
    iconCls: 'text-red-600',
    heading: 'High-Risk URL Evidence Detected',
    body: 'This URL triggered high-risk URL indicators in the active analysis.',
  },
} satisfies Record<Tier, object>;

function historyLabel(item: HistoryItem): string {
  const tier = getTier(
    item.risk_score,
    Boolean(item.verified_official),
  );
  return TIER[tier].heading;
}

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
  reputationEvidence: 'Offline Malicious Reputation Evidence',
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
  reputationEvidence: 'Offline Reputation',
};

function friendlyName(raw: string) {
  return FRIENDLY_NAMES[raw] ?? raw;
}

function chartLabel(raw: string) {
  return CHART_LABELS[raw] ?? raw;
}

// ─── Evidence renderers ───────────────────────────────────────────────────

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function asText(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (Array.isArray(value)) return value.map(asText).filter(Boolean).join(', ');
  return String(value).trim();
}

function asNumber(value: unknown): number | null {
  const numberValue = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(numberValue) ? numberValue : null;
}

function numberText(value: unknown, suffix = ''): string {
  const numberValue = asNumber(value);
  if (numberValue === null) return '';
  return `${numberValue.toFixed(2)}${suffix}`;
}

function rootDomain(host: string): string {
  const normalized = host.trim().toLowerCase().replace(/^www\./, '');
  const parts = normalized.split('.').filter(Boolean);
  if (parts.length <= 2) return normalized;
  const twoLevelSuffixes = new Set([
    'com.my', 'edu.my', 'gov.my', 'org.my', 'net.my',
    'co.uk', 'org.uk', 'ac.uk', 'com.au', 'net.au', 'org.au',
    'co.jp', 'ne.jp', 'co.id', 'or.id', 'com.sg', 'com.br',
  ]);
  const lastTwo = parts.slice(-2).join('.');
  return twoLevelSuffixes.has(lastTwo) && parts.length >= 3
    ? parts.slice(-3).join('.')
    : lastTwo;
}

function normalizedList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map(asText).filter(Boolean);
  }
  const text = asText(value);
  if (!text || text.toLowerCase() === 'none detected') return [];
  return [text];
}

function evidenceStatements(indicator: Indicator): string[] {
  const record = asRecord(indicator.value);
  const score = indicator.risk_points ?? indicator.score ?? 0;
  const statements: string[] = [];

  switch (indicator.name) {
    case 'officialDomain': {
      const domain = asText(record.domain);
      const brand = asText(record.brand || record.matched_brand);
      const registryEntry = asText(
        record.matched_domain || record.matched_official || record.matched_official_source
      );
      const protectedParent = asText(record.protected_parent_domain);
      const matchedTerm = asText(record.matched_term || record.matched_token);
      if (brand) statements.push(`Protected brand: ${brand}.`);
      if (domain) statements.push(`Detected domain: ${domain}.`);
      if (registryEntry) {
        statements.push(`Verified official root: ${rootDomain(registryEntry)}.`);
        if (registryEntry !== rootDomain(registryEntry)) {
          statements.push(`Verified official registry entry: ${registryEntry}.`);
        }
      }
      if (protectedParent) statements.push(`Protected official parent domain: ${protectedParent}.`);
      if (matchedTerm) statements.push(`Protected brand token: ${matchedTerm}.`);
      if (statements.length === 0) {
        statements.push(`Official-domain registry risk points: ${score}/100.`);
      }
      return statements;
    }

    case 'aiModelProbability': {
      const calibrated = numberText(
        record.calibrated_phishing_probability_percent ?? record.phishing_probability_percent,
        '%',
      );
      const raw = numberText(record.raw_phishing_probability_percent, '%');
      const lexical = numberText(record.feature_ai_probability_percent, '%');
      const adjusted = asText(record.adjusted_ai_risk_score);
      if (calibrated) statements.push(`Calibrated AI-assisted probability: ${calibrated}.`);
      if (raw) statements.push(`Raw model probability: ${raw}.`);
      if (lexical) statements.push(`URL lexical-evidence probability: ${lexical}.`);
      if (adjusted) statements.push(`Adjusted AI risk score: ${adjusted}/100.`);
      if (statements.length === 0) statements.push(`AI-assisted risk points: ${score}/100.`);
      return statements;
    }

    case 'brandVerification': {
      const brand = asText(record.brand || record.matched_brand);
      const domain = asText(record.domain || record.root_domain);
      const term = asText(record.matched_term || record.matched_token);
      if (brand) statements.push(`Protected brand evidence: ${brand}.`);
      if (domain) statements.push(`Detected domain: ${domain}.`);
      if (term) statements.push(`Protected brand token: ${term}.`);
      statements.push(`Brand-impersonation risk points: ${score}/100.`);
      return statements;
    }

    case 'homographAttack': {
      const brand = asText(record.brand || record.matched_brand);
      const domain = asText(record.domain || record.root_domain);
      const official = asText(record.matched_official || record.matched_official_source);
      const token = asText(record.matched_term || record.matched_token);
      if (brand) statements.push(`Protected brand evidence: ${brand}.`);
      if (domain) statements.push(`Detected domain: ${domain}.`);
      if (official) statements.push(`Verified official root: ${rootDomain(official)}.`);
      if (token) statements.push(`Similarity token: ${token}.`);
      statements.push(`Homograph and typosquatting risk points: ${score}/100.`);
      return statements;
    }

    case 'urlStructure': {
      const reasons = normalizedList(indicator.value);
      statements.push(`URL structure risk points: ${score}/100.`);
      reasons.forEach(reason => statements.push(`Structure evidence: ${reason}.`));
      return statements;
    }

    case 'suspiciousKeywords': {
      const keywords = normalizedList(indicator.value);
      statements.push(`Suspicious keyword risk points: ${score}/100.`);
      if (keywords.length > 0) {
        statements.push(`Detected keyword tokens: ${keywords.join(', ')}.`);
      } else {
        statements.push('Detected keyword token count: 0.');
      }
      return statements;
    }

    case 'httpsUsage': {
      const scheme = asText(record.submitted_scheme).toUpperCase();
      if (scheme) statements.push(`Submitted URL scheme: ${scheme}.`);
      statements.push('TLS certificate validation scope: URL-scheme analysis.');
      statements.push(`HTTPS usage risk points: ${score}/100.`);
      return statements;
    }

    case 'urlLengthComplexity': {
      const length = asText(record.length);
      const specialCharacters = asText(record.special_characters);
      if (length) statements.push(`URL length: ${length} characters.`);
      if (specialCharacters) statements.push(`Special-character count: ${specialCharacters}.`);
      statements.push(`URL length and complexity risk points: ${score}/100.`);
      return statements;
    }

    case 'reputationEvidence': {
      const matchType = asText(record.match_type);
      const sources = normalizedList(record.sources);
      const contextSources = normalizedList(record.context_sources);
      const contextMatch = record.context_match === true;
      const evidenceScore = asText(record.score || score);
      if (record.match === true) {
        statements.push(`Offline reputation match type: ${matchType || 'recorded evidence'}.`);
        if (sources.length > 0) statements.push(`Offline reputation sources: ${sources.join(', ')}.`);
        statements.push(`Offline reputation evidence score: ${evidenceScore}/100.`);
      } else if (contextMatch) {
        statements.push('Offline reputation context: root-domain historical record.');
        if (contextSources.length > 0) statements.push(`Offline reputation context sources: ${contextSources.join(', ')}.`);
      } else {
        statements.push('Offline reputation match count: 0.');
      }
      return statements;
    }

    default:
      return [`Risk points: ${score}/100.`];
  }
}

function renderEvidenceDetails(indicator: Indicator): React.ReactNode {
  const lines = evidenceStatements(indicator);
  return (
    <ul className="space-y-1 text-xs text-gray-700">
      {lines.map((line, index) => <li key={`${indicator.name}-${index}`}>{line}</li>)}
    </ul>
  );
}

function actionGuidance(result: AIResult, tier: Tier, verifiedOfficial: boolean): string[] {
  const official = result.indicators?.find(item => item.name === 'officialDomain');
  const officialValue = asRecord(official?.value);
  const officialRegistry = asText(officialValue.matched_domain || officialValue.matched_official);
  const guidance = [`Final risk score: ${result.risk_score}/100.`];

  if (verifiedOfficial && officialRegistry) {
    guidance.push(`Verified official-domain registry entry: ${officialRegistry}.`);
    guidance.push(`Service access path: ${officialRegistry}.`);
    return guidance;
  }

  if (tier === 'low-risk') {
    guidance.push('Analysis record: low risk score with the displayed indicator evidence.');
    guidance.push('Service access path: confirm the provider domain through an official channel.');
    return guidance;
  }

  guidance.push('Service access path: use the verified official domain from the provider\'s official channel.');
  if (result.critical_phishing) {
    guidance.push('Critical-rule evidence: recorded in the detailed calculation section.');
  }
  return guidance;
}

function isSingleHttpUrl(value: string): boolean {
  const protocolCount = (value.match(/https?:\/\//gi) ?? []).length;
  if (protocolCount !== 1 || /\s/.test(value)) return false;
  try {
    const parsed = new URL(value);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && Boolean(parsed.hostname);
  } catch {
    return false;
  }
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

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function printReport(result: AIResult, timestamp: string) {
  const win = window.open('', '_blank');
  if (!win) return;

  const verifiedOfficial = isVerifiedOfficialDomain(result);
  const tier = getTier(result.risk_score, verifiedOfficial);
  const guidance = actionGuidance(result, tier, verifiedOfficial);
  const indicators = (result.indicators ?? []).filter(
    indicator => (indicator.used_in_final_score === true || indicator.used_as_reputation_override === true)
      && Boolean(FRIENDLY_NAMES[indicator.name]),
  );
  const indicatorRows = indicators.map(indicator => {
    const evidence = evidenceStatements(indicator).map(escapeHtml).join('<br>');
    const riskPoints = indicator.risk_points ?? indicator.score ?? 0;
    const derivedSafety = indicator.safety_score ?? (100 - riskPoints);
    return `<tr>
      <td>${escapeHtml(friendlyName(indicator.name))}</td>
      <td>${riskPoints}/100</td>
      <td>${derivedSafety}/100</td>
      <td>${evidence}</td>
    </tr>`;
  }).join('');

  win.document.write(`
    <html><head><title>PhishGuard Analysis Report</title>
    <style>body{font-family:Arial,sans-serif;padding:2rem;max-width:900px;margin:auto;color:#111827}h1,h2{color:#3730a3}table{width:100%;border-collapse:collapse;margin:1rem 0}td,th{border:1px solid #d1d5db;padding:8px;text-align:left;vertical-align:top}th{background:#eef2ff}li{margin:.45rem 0}.note{background:#eef2ff;padding:1rem;border-radius:.5rem}</style>
    </head><body>
    <h1>PhishGuard Analysis Report</h1>
    <table>
      <tr><th>URL</th><td style="word-break:break-all">${escapeHtml(result.url)}</td></tr>
      <tr><th>Scan Time</th><td>${escapeHtml(timestamp)}</td></tr>
      <tr><th>Result Classification</th><td>${escapeHtml(TIER[tier].heading)}</td></tr>
      <tr><th>Risk Score</th><td>${result.risk_score} / 100</td></tr>
      <tr><th>Derived Safety Score</th><td>${result.safety_score} / 100</td></tr>
      <tr><th>Critical Rule Trigger</th><td>${result.critical_phishing ? 'Recorded' : '0'}</td></tr>
    </table>
    <div class="note">Derived Safety Score = 100 - Final Risk Score.</div>
    <h2>Action Guidance</h2>
    <ul>${guidance.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>
    <h2>Indicator Evidence</h2>
    <table>
      <tr><th>Indicator</th><th>Risk Points</th><th>Derived Safety Score</th><th>Evidence</th></tr>
      ${indicatorRows}
    </table>
    <h2>Detection Source</h2>
    <p>PhishGuard API: ${escapeHtml(PHISHGUARD_API)}</p>
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
  const [history, setHistory] = useState<HistoryItem[]>(loadHistory);

  const handleClear = () => {
    setUrl('');
    setResult(null);
    setApiError('');
    setScanTime('');
  };

  const handleAnalyze = async () => {
    const trimmed = url.trim();
    if (!trimmed) return;
    if (!isSingleHttpUrl(trimmed)) {
      setApiError('Enter one complete http:// or https:// URL.');
      return;
    }

    setLoading(true);
    setResult(null);
    setApiError('');

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
      const verifiedOfficial = isVerifiedOfficialDomain(data);
      const resultTier = getTier(data.risk_score, verifiedOfficial);
      const histItem: HistoryItem = {
        url: data.url ?? trimmed,
        result: TIER[resultTier].heading,
        decision: data.decision,
        risk_score: data.risk_score,
        safety_score: data.safety_score,
        timestamp: ts,
        critical_phishing: data.critical_phishing,
        verified_official: verifiedOfficial,
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
      setApiError('API request retry required. Submit the URL again.');
    } finally {
      setLoading(false);
    }
  };

  // ─── Derived ──────────────────────────────────────────────────────────────
  const verifiedOfficial = result ? isVerifiedOfficialDomain(result) : false;
  const tier = result
    ? getTier(result.risk_score, verifiedOfficial)
    : null;
  const styles = tier ? TIER[tier] : null;

  const participatingIndicators = result?.indicators?.filter(
    ind => ind.used_in_final_score === true
      && Boolean(FRIENDLY_NAMES[ind.name])
      && typeof ind.weight_percent === 'number'
      && ind.weight_percent > 0
  ) ?? [];

  const ruleOverrideIndicators = result?.indicators?.filter(
    ind => ind.name === 'reputationEvidence'
      && ind.used_as_reputation_override === true
  ) ?? [];

  const displayedIndicators = [
    ...participatingIndicators,
    ...ruleOverrideIndicators,
  ];

  const radarData = displayedIndicators.map(ind => ({
    feature: chartLabel(ind.name),
    score: ind.risk_points ?? ind.score ?? 0,
  }));

  const barData = displayedIndicators.map(ind => ({
    name: chartLabel(ind.name),
    'Risk Points': ind.risk_points ?? ind.score ?? 0,
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
            URL scoring uses the active PhishGuard model and backend evidence rules.
          </p>
        </div>

        {/* ── SECTION 1: URL Input ─────────────────────────────────────────── */}
        <Card className="mb-6 shadow-lg">
          <CardHeader>
            <CardTitle>URL Detection</CardTitle>
            <CardDescription>
              Enter one complete http:// or https:// URL for backend analysis.
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
                  <p className="text-sm text-indigo-500 mt-0.5">Analysis request is active.</p>
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
                      <Badge className={styles.badgeCls}>
                        Risk band: {tier === 'verified-official' ? 'Verified Official Domain' :
                          tier === 'low-risk' ? 'Low Risk' :
                          tier === 'suspicious' ? 'Suspicious' : 'High Risk'}
                      </Badge>
                      {result.critical_phishing && (
                        <Badge className="bg-red-900 text-white">Critical Rule Triggered</Badge>
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
                    <span className="text-sm font-medium text-gray-700">Derived Safety Score</span>
                    <span className={`text-sm font-bold ${safetyScoreColor(result.safety_score)}`}>
                      {result.safety_score} / 100
                    </span>
                  </div>
                  <Progress value={result.safety_score} className="h-3" />
                  <p className="text-xs text-gray-400 mt-1">Formula: 100 − Final Risk Score</p>
                </div>

                {/* P0.3: weighted scoring note */}
                <div className="bg-gray-50 border border-gray-200 rounded-md p-3 text-xs text-gray-500">
                  <p>
                    Final risk score records the base weighted score and the backend rule evaluations
                    applied to this URL.
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
                    <p className="font-semibold">Backend score construction</p>
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
                      Base weighted score before overrides = {result.score_audit?.weighted_score_before_overrides}
                    </p>
                    <p className="font-mono">
                      Final risk score = {result.score_audit?.final_risk_score}
                    </p>
                    {ruleOverrideIndicators.map(indicator => (
                      <div
                        key={indicator.name}
                        className="mt-2 rounded border border-indigo-200 bg-white/70 p-2"
                      >
                        <p className="font-semibold">
                          {friendlyName(indicator.name)} — Rule Override
                        </p>
                        <p className="font-mono">
                          Weighted contribution = 0%; evidence score = {indicator.risk_points ?? 0}/100
                        </p>
                        <div className="mt-1">{renderEvidenceDetails(indicator)}</div>
                      </div>
                    ))}
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
                    <p className="font-mono">Derived Safety Score = 100 − Final Risk Score</p>
                    <p className="font-semibold mt-2">Backend rule evaluation</p>
                    <ul className="ml-4 space-y-0.5 list-disc list-inside">
                      {result.critical_phishing && <li>Critical-evidence aggregation applied.</li>}
                      {ruleOverrideIndicators.some(indicator => (indicator.risk_points ?? indicator.score ?? 0) > 0) && (
                        <li>Offline malicious reputation evidence applied.</li>
                      )}
                      {verifiedOfficial && <li>Verified official-domain registry protection applied.</li>}
                      {!result.critical_phishing
                        && !verifiedOfficial
                        && !ruleOverrideIndicators.some(indicator => (indicator.risk_points ?? indicator.score ?? 0) > 0)
                        && <li>Final score equals the evaluated base score.</li>}
                    </ul>
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
                        Evidence Summary
                      </h3>
                      <div className="space-y-3">
                        {displayedIndicators.map(indicator => (
                          <div
                            key={indicator.name}
                            className={`bg-white p-3 rounded border-l-4 ${styles.leftBorder} text-sm text-gray-700`}
                          >
                            <p className="mb-1 font-medium text-gray-900">{friendlyName(indicator.name)}</p>
                            {renderEvidenceDetails(indicator)}
                          </div>
                        ))}
                      </div>
                    </div>
                  </TabsContent>

                  {/* TAB 2 — Features */}
                  <TabsContent value="features" className="mt-5">
                    {displayedIndicators.length > 0 ? (
                      <div className="grid gap-4 md:grid-cols-2">
                        {displayedIndicators.map((ind, i) => {
                          const status = (ind.status ?? '').toLowerCase();
                          const isDanger = status === 'danger';
                          const isWarning = status === 'warning';
                          const isSafe = status === 'safe';
                          const isAI = ind.name === 'aiModelProbability';
                          const isRuleOverride = ind.name === 'reputationEvidence'
                            && ind.used_as_reputation_override === true;

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
                                {isRuleOverride && (
                                  <Badge
                                    variant="outline"
                                    className="ml-2 mb-3 border-purple-300 text-xs text-purple-700"
                                  >
                                    Rule Override · 0% Weighted Contribution
                                  </Badge>
                                )}

                                {/* AI Model Probability — all fields sourced from indicator.value */}
                                {isAI && (() => {
                                  const v = (ind.value && typeof ind.value === 'object')
                                    ? ind.value as Record<string, unknown>
                                    : {};

                                  const fmt = (field: unknown, suffix = '') => {
                                    if (field === undefined || field === null || field === '') {
                                      return <span className="text-gray-400">—</span>;
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
                                  <div className="mt-2 mb-3">
                                    <div className="flex justify-between text-xs mb-1">
                                      <span className="text-gray-500">Risk Points</span>
                                      <span className="font-medium">{ind.risk_points} / 100</span>
                                    </div>
                                    <Progress value={ind.risk_points} className="h-1.5" />
                                    <p className="mt-1 text-xs text-gray-500">
                                      Derived Safety Score: {safetyPct} / 100 (100 − Risk Points)
                                    </p>
                                  </div>
                                )}

                                <div className="mt-3 border-t border-gray-100 pt-2">
                                  <p className="mb-1 text-xs text-gray-400">Evidence Details</p>
                                  {renderEvidenceDetails(ind)}
                                </div>
                              </CardContent>
                            </Card>
                          );
                        })}
                      </div>
                    ) : (
                      <p className="text-sm text-gray-400 text-center py-8">
                        Indicator dataset entries: 0.
                      </p>
                    )}
                  </TabsContent>

                  {/* TAB 3 — Visualization */}
                  <TabsContent value="visualization" className="mt-5 space-y-8">
                    {radarData.length > 0 ? (
                      <>
                        {/* Radar */}
                        <div>
                          <h3 className="font-medium mb-1">Security Indicator Risk Points</h3>
                          <p className="text-xs text-gray-400 mb-4">Each value equals the risk points returned by the backend.</p>
                          <ResponsiveContainer width="100%" height={380}>
                            <RadarChart data={radarData}>
                              <PolarGrid />
                              <PolarAngleAxis dataKey="feature" tick={{ fontSize: 11 }} />
                              <PolarRadiusAxis angle={90} domain={[0, 100]} tick={{ fontSize: 10 }} />
                              <Radar
                                name="Risk Points"
                                dataKey="score"
                                stroke="#b91c1c"
                                fill="#dc2626"
                                fillOpacity={0.55}
                              />
                              <Tooltip />
                            </RadarChart>
                          </ResponsiveContainer>
                        </div>

                        {/* Bar */}
                        <div>
                          <h3 className="font-medium mb-1">Indicator Risk Points</h3>
                          <p className="text-xs text-gray-400 mb-4">Each value equals the risk points returned by the backend.</p>
                          <ResponsiveContainer width="100%" height={300}>
                            <BarChart data={barData}>
                              <CartesianGrid strokeDasharray="3 3" />
                              <XAxis dataKey="name" tick={{ fontSize: 10 }} />
                              <YAxis domain={[0, 100]} />
                              <Tooltip />
                              <Legend />
                              <Bar dataKey="Risk Points" fill="#dc2626" />
                            </BarChart>
                          </ResponsiveContainer>
                        </div>
                      </>
                    ) : (
                      <p className="text-sm text-gray-400 text-center py-8">
                        Visualization dataset entries: 0.
                      </p>
                    )}
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>

            {/* ── SECTION 5: Action guidance ─────────────────────────────── */}
            <Card className="shadow">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-indigo-500" />
                  Action Guidance
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2">
                  {actionGuidance(result, tier, verifiedOfficial).map((item, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm text-gray-700">
                      <span className="text-indigo-500 mt-0.5 shrink-0">•</span>
                      {item}
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>

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
                          <th className="text-left py-2 font-medium">Critical Rule</th>
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
                              }`}>{historyLabel(h)}</Badge>
                            </td>
                            <td className="py-2 pr-3 font-mono">{h.risk_score}</td>
                            <td className="py-2 text-gray-600">{h.critical_phishing ? 'Recorded' : '0'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-xs text-gray-400">Scan history entries: 0.</p>
                )}

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
                <CardDescription>Select a URL to load it into the analyzer</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-2 sm:grid-cols-2">
                  <Button
                    variant="outline"
                    onClick={() => setUrl('https://www.google.com')}
                    className="justify-start text-sm"
                  >
                    ✅ Verified official registry — https://www.google.com
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => setUrl('https://www.goog1e.com')}
                    className="justify-start text-sm"
                  >
                    ⚠ Brand-similarity evidence — goog1e.com
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => setUrl('http://paypal-login-security.com')}
                    className="justify-start text-sm"
                  >
                    ⚠ Brand and credential evidence — paypal-login-security.com
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => setUrl('http://192.168.1.10/login')}
                    className="justify-start text-sm"
                  >
                    ⚠ IP-host structure evidence — http://192.168.1.10/login
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
                          <th className="text-left py-2 font-medium">Critical Rule</th>
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
                              }`}>{historyLabel(h)}</Badge>
                            </td>
                            <td className="py-2 pr-3 font-mono">{h.risk_score}</td>
                            <td className="py-2 text-gray-600">{h.critical_phishing ? 'Recorded' : '0'}</td>
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
