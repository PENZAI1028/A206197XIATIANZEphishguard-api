import { useEffect, useMemo, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { Badge } from './ui/badge';
import { ScrollArea } from './ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line } from 'recharts';
import { Shield, TrendingUp, Activity, AlertTriangle, CheckCircle, XCircle, LogOut, Download, Filter, Users, ArrowLeft, BadgeCheck } from 'lucide-react';

type RiskBandKey = 'trusted' | 'lowRisk' | 'suspicious' | 'highRisk';
type CriticalRuleFilter = 'all' | 'applied' | 'not-applied';

interface RiskBandCounts {
  trusted: number;
  lowRisk: number;
  suspicious: number;
  highRisk: number;
}

interface TopHighRiskSubmittedHost {
  host: string;
  detectionCount: number;
  latestSubmittedUrl: string;
  latestRiskScore: number;
  latestCriticalRuleApplied: boolean;
  criticalRuleApplications: number;
  latestTimestamp: string;
}

interface GlobalStatistics {
  totalScans: number;
  phishingDetected?: number;
  safeDetected?: number;
  avgRiskScore: number;
  phishingRate?: number;
  uniqueUsers: number;
  anonymousScans: number;
  monthlyStats: Record<string, { total: number; highRisk: number }>;
  riskBands?: RiskBandCounts;
  criticalRuleApplications?: number;
  topHighRiskSubmittedHosts?: TopHighRiskSubmittedHost[];
}

interface Detection {
  url: string;
  riskScore: number;
  safetyScore?: number;
  isPhishing?: boolean;
  result?: string;
  decision?: string;
  critical_phishing?: boolean;
  timestamp: string;
  userId: string;
  userEmail: string;
  id: string;
  indicators?: unknown[];
}

interface AdminDashboardProps {
  accessToken: string;
  userEmail: string;
  userName: string;
  onLogout: () => void;
  onBackToDetector?: () => void;
}

const RISK_BANDS: Array<{
  key: RiskBandKey;
  label: string;
  range: string;
  min: number;
  max: number;
  color: string;
  badge: string;
}> = [
  { key: 'trusted', label: 'Trusted', range: '0–19', min: 0, max: 19, color: '#22c55e', badge: 'bg-green-600 text-white' },
  { key: 'lowRisk', label: 'Low Risk', range: '20–44', min: 20, max: 44, color: '#3b82f6', badge: 'bg-blue-600 text-white' },
  { key: 'suspicious', label: 'Suspicious', range: '45–79', min: 45, max: 79, color: '#eab308', badge: 'bg-yellow-600 text-white' },
  { key: 'highRisk', label: 'High Risk', range: '80–100', min: 80, max: 100, color: '#dc2626', badge: 'bg-red-700 text-white' },
];

function getRiskBand(score: number) {
  if (score < 20) return RISK_BANDS[0];
  if (score < 45) return RISK_BANDS[1];
  if (score < 80) return RISK_BANDS[2];
  return RISK_BANDS[3];
}

function getRiskBandCounts(detections: Detection[]): RiskBandCounts {
  const counts: RiskBandCounts = { trusted: 0, lowRisk: 0, suspicious: 0, highRisk: 0 };
  for (const detection of detections) {
    if (!detection || typeof detection.riskScore !== 'number') continue;
    counts[getRiskBand(detection.riskScore).key] += 1;
  }
  return counts;
}

function hasCriticalRule(detection: Detection) {
  return detection.critical_phishing === true;
}

function formatTimestamp(value: string) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function getLocalTopHighRiskHosts(detections: Detection[]): TopHighRiskSubmittedHost[] {
  const entries = new Map<string, {
    host: string;
    detectionCount: number;
    latest: Detection;
    criticalRuleApplications: number;
  }>();

  for (const detection of detections) {
    if (!detection || detection.riskScore < 80) continue;
    try {
      const host = new URL(detection.url).hostname.toLowerCase();
      if (!host) continue;
      const current = entries.get(host) || {
        host,
        detectionCount: 0,
        latest: detection,
        criticalRuleApplications: 0,
      };
      current.detectionCount += 1;
      if (hasCriticalRule(detection)) current.criticalRuleApplications += 1;
      if (new Date(detection.timestamp).getTime() > new Date(current.latest.timestamp).getTime()) {
        current.latest = detection;
      }
      entries.set(host, current);
    } catch {
      // Invalid historic URLs have no usable hostname for this evidence table.
    }
  }

  return [...entries.values()]
    .sort((a, b) => b.detectionCount - a.detectionCount || new Date(b.latest.timestamp).getTime() - new Date(a.latest.timestamp).getTime())
    .slice(0, 10)
    .map((entry) => ({
      host: entry.host,
      detectionCount: entry.detectionCount,
      latestSubmittedUrl: entry.latest.url,
      latestRiskScore: entry.latest.riskScore,
      latestCriticalRuleApplied: hasCriticalRule(entry.latest),
      criticalRuleApplications: entry.criticalRuleApplications,
      latestTimestamp: entry.latest.timestamp,
    }));
}

function RiskBandBadge({ score }: { score: number }) {
  const band = getRiskBand(score);
  return <Badge className={band.badge}>{band.label}</Badge>;
}

function CriticalRuleBadge({ detection }: { detection: Detection }) {
  if (!hasCriticalRule(detection)) return <span className="text-sm text-gray-500">—</span>;
  return (
    <Badge className="bg-amber-700 text-white">
      <BadgeCheck className="w-3 h-3 mr-1" />
      Applied
    </Badge>
  );
}

export function AdminDashboard({ accessToken: _accessToken, userEmail, userName, onLogout, onBackToDetector }: AdminDashboardProps) {
  const [statistics, setStatistics] = useState<GlobalStatistics | null>(null);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [filteredDetections, setFilteredDetections] = useState<Detection[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCases, setSelectedCases] = useState<Set<string>>(new Set());

  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [riskLevel, setRiskLevel] = useState('all');
  const [criticalRuleFilter, setCriticalRuleFilter] = useState<CriticalRuleFilter>('all');
  const [domainFilter, setDomainFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');

  useEffect(() => {
    fetchData();
  }, []);

  useEffect(() => {
    applyFilters();
  }, [detections, startDate, endDate, riskLevel, criticalRuleFilter, domainFilter, userFilter]);

  const fetchData = async () => {
    try {
      const { projectId, publicAnonKey } = await import('../../../utils/supabase/info');
      const { getSupabaseClient } = await import('../../../utils/supabase/client');
      const supabase = getSupabaseClient();
      const { data: { session }, error: sessionError } = await supabase.auth.getSession();

      if (sessionError || !session?.access_token) {
        alert('Your session has expired. Please log in again.');
        onLogout();
        return;
      }

      const headers = {
        apikey: publicAnonKey,
        Authorization: `Bearer ${session.access_token}`,
      };
      const baseUrl = `https://${projectId}.supabase.co/functions/v1/make-server-358bdfd0`;
      const [statsResponse, detectionsResponse] = await Promise.all([
        fetch(`${baseUrl}/admin/statistics`, { headers }),
        fetch(`${baseUrl}/admin/detections`, { headers }),
      ]);

      if (statsResponse.status === 401 || detectionsResponse.status === 401) {
        alert('Authentication failed. Please log in again.');
        onLogout();
        return;
      }

      if (statsResponse.ok) setStatistics(await statsResponse.json());
      else console.error('Failed to fetch administrator statistics:', await statsResponse.text());

      if (detectionsResponse.ok) {
        const data = await detectionsResponse.json();
        setDetections(data.detections || []);
      } else {
        console.error('Failed to fetch administrator detection records:', await detectionsResponse.text());
      }
    } catch (error) {
      console.error('Error fetching administrator data:', error);
      alert('An error occurred while loading administrator data.');
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = detections.filter((detection) => detection && typeof detection.riskScore === 'number');

    if (startDate) {
      const from = new Date(`${startDate}T00:00:00`);
      filtered = filtered.filter((detection) => new Date(detection.timestamp) >= from);
    }
    if (endDate) {
      const through = new Date(`${endDate}T23:59:59.999`);
      filtered = filtered.filter((detection) => new Date(detection.timestamp) <= through);
    }

    if (riskLevel !== 'all') {
      filtered = filtered.filter((detection) => getRiskBand(detection.riskScore).key === riskLevel);
    }
    if (criticalRuleFilter === 'applied') {
      filtered = filtered.filter(hasCriticalRule);
    } else if (criticalRuleFilter === 'not-applied') {
      filtered = filtered.filter((detection) => !hasCriticalRule(detection));
    }
    if (domainFilter) {
      const value = domainFilter.toLowerCase();
      filtered = filtered.filter((detection) => detection.url?.toLowerCase().includes(value));
    }
    if (userFilter) {
      const value = userFilter.toLowerCase();
      filtered = filtered.filter((detection) =>
        detection.userEmail?.toLowerCase().includes(value) || detection.userId?.toLowerCase() === value,
      );
    }

    setFilteredDetections(filtered);
  };

  const clearFilters = () => {
    setStartDate('');
    setEndDate('');
    setRiskLevel('all');
    setCriticalRuleFilter('all');
    setDomainFilter('');
    setUserFilter('');
  };

  const toggleCaseSelection = (id: string) => {
    setSelectedCases((current) => {
      const next = new Set(current);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const exportSelectedCases = async () => {
    if (selectedCases.size === 0) {
      alert('Select at least one case to export.');
      return;
    }

    try {
      const { projectId, publicAnonKey } = await import('../../../utils/supabase/info');
      const { getSupabaseClient } = await import('../../../utils/supabase/client');
      const { data: { session } } = await getSupabaseClient().auth.getSession();
      if (!session?.access_token) {
        alert('Session expired. Please log in again.');
        return;
      }

      const response = await fetch(
        `https://${projectId}.supabase.co/functions/v1/make-server-358bdfd0/admin/export`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            apikey: publicAnonKey,
            Authorization: `Bearer ${session.access_token}`,
          },
          body: JSON.stringify({ caseIds: [...selectedCases] }),
        },
      );

      if (!response.ok) {
        alert('The selected cases were not exported.');
        return;
      }

      const data = await response.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = `phishguard-cases-${new Date().toISOString().slice(0, 10)}.json`;
      link.click();
      window.URL.revokeObjectURL(downloadUrl);
      setSelectedCases(new Set());
    } catch (error) {
      console.error('Error exporting selected cases:', error);
      alert('The selected cases were not exported.');
    }
  };

  const bandCounts = useMemo(
    () => statistics?.riskBands || getRiskBandCounts(detections),
    [statistics, detections],
  );

  const criticalRuleApplications = useMemo(
    () => statistics?.criticalRuleApplications ?? detections.filter(hasCriticalRule).length,
    [statistics, detections],
  );

  const topHosts = useMemo(
    () => statistics?.topHighRiskSubmittedHosts || getLocalTopHighRiskHosts(detections),
    [statistics, detections],
  );

  const pieChartData = useMemo(
    () => RISK_BANDS.map((band) => ({
      name: `${band.label} (${band.range})`,
      value: bandCounts[band.key],
      color: band.color,
    })),
    [bandCounts],
  );

  const monthlyChartData = useMemo(() => {
    if (!statistics?.monthlyStats) return [];
    return Object.entries(statistics.monthlyStats)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([month, data]) => ({
        month: `${month.slice(5, 7)}/${month.slice(0, 4)}`,
        'Total Scans': data.total,
        'High Risk': data.highRisk,
      }));
  }, [statistics]);

  const highRiskCount = bandCounts.highRisk;

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="text-center">
          <Shield className="w-12 h-12 text-indigo-600 animate-pulse mx-auto mb-4" />
          <p className="text-gray-600">Loading administrator dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-4 md:p-8">
      <div className="max-w-7xl mx-auto">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between mb-8">
          <div className="flex items-center gap-3">
            <Shield className="w-10 h-10 text-indigo-600" />
            <div>
              <h1>Administrator Dashboard</h1>
              <p className="text-gray-600">Backend-recorded risk bands and rule-application evidence</p>
            </div>
          </div>
          <div className="flex items-center gap-3 flex-wrap md:justify-end">
            {onBackToDetector && (
              <Button variant="outline" onClick={onBackToDetector}>
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back to Detector
              </Button>
            )}
            <div className="text-right">
              <p className="text-sm font-medium">{userName}</p>
              <p className="text-xs text-gray-500">{userEmail}</p>
            </div>
            <Button variant="outline" onClick={onLogout}>
              <LogOut className="w-4 h-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>

        <div className="grid gap-6 md:grid-cols-4 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{statistics?.totalScans || detections.length}</div>
              <p className="text-xs text-muted-foreground">Saved administrator records</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">High-Risk Results</CardTitle>
              <AlertTriangle className="h-4 w-4 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">{highRiskCount}</div>
              <p className="text-xs text-muted-foreground">Final risk score 80–100</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Critical Rule Applications</CardTitle>
              <BadgeCheck className="h-4 w-4 text-amber-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-amber-700">{criticalRuleApplications}</div>
              <p className="text-xs text-muted-foreground">Critical-evidence aggregation applied</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Average Risk Score</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{statistics?.avgRiskScore || 0}</div>
              <p className="text-xs text-muted-foreground">Final score out of 100</p>
            </CardContent>
          </Card>
        </div>

        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList className="flex flex-wrap h-auto">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="logs">Scan Logs</TabsTrigger>
            <TabsTrigger value="analysis">Risk Analysis</TabsTrigger>
            <TabsTrigger value="export">Export Cases</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <Card className="border-indigo-200 bg-indigo-50/60">
              <CardContent className="pt-5 text-sm text-indigo-900">
                <strong>Backend risk-band configuration:</strong> Trusted 0–19, Low Risk 20–44, Suspicious 45–79, High Risk 80–100. Critical Rule Application is a separate backend rule-evaluation status.
              </CardContent>
            </Card>

            <div className="grid gap-6 md:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>Final Risk-Band Distribution</CardTitle>
                  <CardDescription>Saved records grouped by backend final risk score</CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={pieChartData}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        label={({ name, percent }) => `${name}: ${((percent || 0) * 100).toFixed(0)}%`}
                        outerRadius={80}
                        dataKey="value"
                      >
                        {pieChartData.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Monthly Scan Trends</CardTitle>
                  <CardDescription>Saved high-risk results per month: final risk score 80–100</CardDescription>
                </CardHeader>
                <CardContent>
                  {monthlyChartData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={300}>
                      <LineChart data={monthlyChartData}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="month" />
                        <YAxis />
                        <Tooltip />
                        <Legend />
                        <Line type="monotone" dataKey="Total Scans" stroke="#4f46e5" strokeWidth={2} dot={{ r: 4 }} />
                        <Line type="monotone" dataKey="High Risk" stroke="#dc2626" strokeWidth={2} dot={{ r: 4 }} />
                      </LineChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-[300px] flex items-center justify-center text-gray-500">No monthly records are available.</div>
                  )}
                </CardContent>
              </Card>
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Top High-Risk Submitted Hosts</CardTitle>
                <CardDescription>Hosts are ranked by saved high-risk submitted URLs. Each row preserves the latest submitted URL and stored evidence status.</CardDescription>
              </CardHeader>
              <CardContent>
                {topHosts.length > 0 ? (
                  <div className="space-y-3">
                    {topHosts.map((entry) => (
                      <div key={entry.host} className="rounded-lg border border-red-200 bg-red-50 p-4 space-y-2">
                        <div className="flex flex-wrap items-center gap-2 justify-between">
                          <span className="font-semibold text-red-900 break-all">Host: {entry.host}</span>
                          <Badge variant="destructive">{entry.detectionCount} high-risk submission{entry.detectionCount === 1 ? '' : 's'}</Badge>
                        </div>
                        <p className="text-sm break-all"><span className="font-medium">Latest submitted URL:</span> {entry.latestSubmittedUrl}</p>
                        <div className="flex flex-wrap gap-3 text-sm text-gray-700">
                          <span>Latest final risk: <strong>{entry.latestRiskScore}/100</strong></span>
                          <span>Latest critical rule: <strong>{entry.latestCriticalRuleApplied ? 'Applied' : '—'}</strong></span>
                          <span>Critical-rule applications: <strong>{entry.criticalRuleApplications}</strong></span>
                          <span>Latest record: {formatTimestamp(entry.latestTimestamp)}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center text-gray-500 py-8">No saved high-risk submitted hosts are available.</div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="logs">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2"><Filter className="w-5 h-5" />Search and Filter Scan Logs</CardTitle>
                <CardDescription>Filter saved records by backend risk band, critical-rule application, date, host text, or user.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-6">
                  <div className="space-y-2"><Label>Start Date</Label><Input type="date" value={startDate} onChange={(event) => setStartDate(event.target.value)} /></div>
                  <div className="space-y-2"><Label>End Date</Label><Input type="date" value={endDate} onChange={(event) => setEndDate(event.target.value)} /></div>
                  <div className="space-y-2">
                    <Label>Risk Band</Label>
                    <Select value={riskLevel} onValueChange={setRiskLevel}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Risk Bands</SelectItem>
                        <SelectItem value="trusted">Trusted (0–19)</SelectItem>
                        <SelectItem value="lowRisk">Low Risk (20–44)</SelectItem>
                        <SelectItem value="suspicious">Suspicious (45–79)</SelectItem>
                        <SelectItem value="highRisk">High Risk (80–100)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Critical Rule</Label>
                    <Select value={criticalRuleFilter} onValueChange={(value) => setCriticalRuleFilter(value as CriticalRuleFilter)}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Rule States</SelectItem>
                        <SelectItem value="applied">Applied</SelectItem>
                        <SelectItem value="not-applied">Not Applied</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2"><Label>Host or URL</Label><Input placeholder="Filter by host or URL" value={domainFilter} onChange={(event) => setDomainFilter(event.target.value)} /></div>
                  <div className="space-y-2"><Label>User</Label><Input placeholder="Filter by user" value={userFilter} onChange={(event) => setUserFilter(event.target.value)} /></div>
                </div>

                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm text-gray-600">Showing {filteredDetections.length} of {detections.length} saved records</p>
                  <Button variant="outline" size="sm" onClick={clearFilters}>Clear Filters</Button>
                </div>

                {filteredDetections.length > 0 ? (
                  <ScrollArea className="h-[600px]">
                    <div className="space-y-3">
                      {filteredDetections.map((detection) => (
                        <Card key={detection.id} className="hover:shadow-md transition-shadow">
                          <CardContent className="pt-4">
                            <div className="space-y-2">
                              <div className="flex flex-wrap items-center gap-2">
                                <RiskBandBadge score={detection.riskScore} />
                                <Badge variant="outline">Risk: {detection.riskScore}/100</Badge>
                                <CriticalRuleBadge detection={detection} />
                                <Badge variant="secondary">{detection.userId === 'anonymous' ? 'Anonymous' : detection.userEmail}</Badge>
                              </div>
                              <p className="text-sm font-medium break-all">{detection.url}</p>
                              <p className="text-xs text-gray-500">{formatTimestamp(detection.timestamp)}</p>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </ScrollArea>
                ) : (
                  <div className="h-[240px] flex items-center justify-center text-gray-500">No saved records match the active filters.</div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="analysis">
            <Card>
              <CardHeader>
                <CardTitle>Risk-Band and Rule-Application Analysis</CardTitle>
                <CardDescription>All score bands follow the active backend configuration. Critical Rule Application remains separate from risk bands.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <ResponsiveContainer width="100%" height={320}>
                  <BarChart data={RISK_BANDS.map((band) => ({ name: `${band.label} (${band.range})`, count: bandCounts[band.key] }))}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="count" fill="#4f46e5" />
                  </BarChart>
                </ResponsiveContainer>

                <div className="grid gap-4 md:grid-cols-2">
                  <Card>
                    <CardHeader><CardTitle className="text-base">Risk-Band Summary</CardTitle></CardHeader>
                    <CardContent className="space-y-2">
                      {RISK_BANDS.map((band) => (
                        <div key={band.key} className="flex items-center justify-between rounded bg-gray-50 p-2">
                          <span>{band.label} ({band.range})</span>
                          <Badge className={band.badge}>{bandCounts[band.key]}</Badge>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader><CardTitle className="text-base">Critical Rule Application</CardTitle></CardHeader>
                    <CardContent>
                      <div className="flex items-center justify-between rounded bg-amber-50 p-3 border border-amber-200">
                        <span>Applied records</span>
                        <Badge className="bg-amber-700 text-white">{criticalRuleApplications}</Badge>
                      </div>
                      <p className="mt-3 text-sm text-gray-600">This count records backend critical-evidence aggregation. It remains independent from the four final risk bands.</p>
                    </CardContent>
                  </Card>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="export">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2"><Download className="w-5 h-5" />Export Saved Cases</CardTitle>
                <CardDescription>Select saved detection records for anonymized training, awareness, or incident-report exports.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between bg-blue-50 p-4 rounded-lg border border-blue-200">
                  <div>
                    <p className="font-medium text-blue-900">{selectedCases.size} case{selectedCases.size === 1 ? '' : 's'} selected</p>
                    <p className="text-sm text-blue-700">Exported records remove user identity fields.</p>
                  </div>
                  <div className="flex gap-2">
                    {selectedCases.size > 0 && <Button variant="outline" onClick={() => setSelectedCases(new Set())}>Clear Selection</Button>}
                    <Button onClick={exportSelectedCases} disabled={selectedCases.size === 0}><Download className="w-4 h-4 mr-2" />Export Selected</Button>
                  </div>
                </div>

                {filteredDetections.length > 0 ? (
                  <ScrollArea className="h-[500px]">
                    <div className="space-y-3">
                      {filteredDetections.map((detection) => (
                        <Card
                          key={detection.id}
                          className={`cursor-pointer transition-all ${selectedCases.has(detection.id) ? 'border-blue-500 bg-blue-50' : 'hover:shadow-md'}`}
                          onClick={() => toggleCaseSelection(detection.id)}
                        >
                          <CardContent className="pt-4">
                            <div className="flex items-start gap-4">
                              <input
                                type="checkbox"
                                checked={selectedCases.has(detection.id)}
                                onChange={() => toggleCaseSelection(detection.id)}
                                onClick={(event) => event.stopPropagation()}
                                className="mt-1"
                              />
                              <div className="flex-1 space-y-2">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <RiskBandBadge score={detection.riskScore} />
                                  <Badge variant="outline">Risk: {detection.riskScore}/100</Badge>
                                  <CriticalRuleBadge detection={detection} />
                                </div>
                                <p className="text-sm font-medium break-all">{detection.url}</p>
                                <p className="text-xs text-gray-500">{formatTimestamp(detection.timestamp)}</p>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </ScrollArea>
                ) : (
                  <div className="h-[240px] flex items-center justify-center text-gray-500">No saved cases are available for export.</div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
