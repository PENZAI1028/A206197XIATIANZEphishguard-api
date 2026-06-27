import { useEffect, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { Badge } from './ui/badge';
import { ScrollArea } from './ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line } from 'recharts';
import { Shield, TrendingUp, Activity, AlertTriangle, CheckCircle, XCircle, LogOut, Search, Download, Filter, Users, ArrowLeft } from 'lucide-react';

interface GlobalStatistics {
  totalScans: number;
  phishingDetected: number;
  safeDetected: number;
  avgRiskScore: number;
  phishingRate: number;
  uniqueUsers: number;
  anonymousScans: number;
  monthlyStats: {
    [key: string]: { total: number; highRisk: number };
  };
  topAbusedDomains: Array<{ domain: string; count: number }>;
}

interface Detection {
  url: string;
  riskScore: number;
  isPhishing: boolean;
  timestamp: string;
  userId: string;
  userEmail: string;
  id: string;
  features: any;
}

interface AdminDashboardProps {
  accessToken: string;
  userEmail: string;
  userName: string;
  onLogout: () => void;
  onBackToDetector?: () => void;
}

export function AdminDashboard({ accessToken, userEmail, userName, onLogout, onBackToDetector }: AdminDashboardProps) {
  const [statistics, setStatistics] = useState<GlobalStatistics | null>(null);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [filteredDetections, setFilteredDetections] = useState<Detection[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCases, setSelectedCases] = useState<Set<string>>(new Set());

  // Filter states
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [riskLevel, setRiskLevel] = useState('all');
  const [domainFilter, setDomainFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');

  useEffect(() => {
    fetchData();
  }, []);

  useEffect(() => {
    applyFilters();
  }, [detections, startDate, endDate, riskLevel, domainFilter, userFilter]);

  const fetchData = async () => {
    try {
      const { projectId, publicAnonKey } = await import('../../../utils/supabase/info');
      const { getSupabaseClient } = await import('../../../utils/supabase/client');
      const supabase = getSupabaseClient();

      // Get fresh session to ensure token is valid
      const { data: { session }, error: sessionError } = await supabase.auth.getSession();

      if (sessionError || !session?.access_token) {
        console.error('Session error:', sessionError);
        alert('Your session has expired. Please log in again.');
        onLogout();
        return;
      }
      
      const currentAccessToken = session.access_token;
      
      console.log('Fetching admin data with token:', currentAccessToken.substring(0, 20) + '...');
      console.log('User metadata:', session.user?.user_metadata);
      
      // Fetch global statistics
      const statsResponse = await fetch(
        `https://${projectId}.supabase.co/functions/v1/make-server-358bdfd0/admin/statistics`,
        {
          headers: {
            'apikey': publicAnonKey,
            'Authorization': `Bearer ${currentAccessToken}`,
          },
        }
      );

      if (statsResponse.ok) {
        const statsData = await statsResponse.json();
        setStatistics(statsData);
      } else {
        const errorText = await statsResponse.text();
        console.error('Failed to fetch statistics:', errorText);
        if (statsResponse.status === 401) {
          alert('Authentication failed. Please log in again.');
          onLogout();
          return;
        }
      }

      // Fetch all detections
      const detectionsResponse = await fetch(
        `https://${projectId}.supabase.co/functions/v1/make-server-358bdfd0/admin/detections`,
        {
          headers: {
            'apikey': publicAnonKey,
            'Authorization': `Bearer ${currentAccessToken}`,
          },
        }
      );

      if (detectionsResponse.ok) {
        const detectionsData = await detectionsResponse.json();
        setDetections(detectionsData.detections || []);
      } else {
        const errorText = await detectionsResponse.text();
        console.error('Failed to fetch detections:', errorText);
        if (detectionsResponse.status === 401) {
          alert('Authentication failed. Please log in again.');
          onLogout();
          return;
        }
      }
    } catch (error) {
      console.error('Error fetching data:', error);
      alert('An error occurred while fetching data. Please try logging in again.');
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = () => {
    // Filter out null/undefined values first
    let filtered = detections.filter(d => d != null);

    if (startDate) {
      filtered = filtered.filter(d => d.timestamp && new Date(d.timestamp) >= new Date(startDate));
    }

    if (endDate) {
      filtered = filtered.filter(d => d.timestamp && new Date(d.timestamp) <= new Date(endDate));
    }

    if (riskLevel !== 'all') {
      if (riskLevel === 'trusted') {
        filtered = filtered.filter(d => d.riskScore != null && d.riskScore < 20);
      } else if (riskLevel === 'low-risk') {
        filtered = filtered.filter(d => d.riskScore != null && d.riskScore >= 20 && d.riskScore < 40);
      } else if (riskLevel === 'suspicious') {
        filtered = filtered.filter(d => d.riskScore != null && d.riskScore >= 40 && d.riskScore < 60);
      } else if (riskLevel === 'high-risk') {
        filtered = filtered.filter(d => d.riskScore != null && d.riskScore >= 60 && d.riskScore < 80);
      } else if (riskLevel === 'critical') {
        filtered = filtered.filter(d => d.riskScore != null && d.riskScore >= 80);
      }
    }

    if (domainFilter) {
      filtered = filtered.filter(d =>
        d.url && d.url.toLowerCase().includes(domainFilter.toLowerCase())
      );
    }

    if (userFilter) {
      filtered = filtered.filter(d =>
        (d.userEmail && d.userEmail.toLowerCase().includes(userFilter.toLowerCase())) ||
        d.userId === userFilter
      );
    }

    setFilteredDetections(filtered);
  };

  const clearFilters = () => {
    setStartDate('');
    setEndDate('');
    setRiskLevel('all');
    setDomainFilter('');
    setUserFilter('');
  };

  const toggleCaseSelection = (id: string) => {
    const newSelection = new Set(selectedCases);
    if (newSelection.has(id)) {
      newSelection.delete(id);
    } else {
      newSelection.add(id);
    }
    setSelectedCases(newSelection);
  };

  const exportSelectedCases = async () => {
    if (selectedCases.size === 0) {
      alert('Please select at least one case to export');
      return;
    }

    try {
      const { projectId, publicAnonKey } = await import('../../../utils/supabase/info');
      const { getSupabaseClient } = await import('../../../utils/supabase/client');
      const supabase = getSupabaseClient();

      // Get fresh session
      const { data: { session } } = await supabase.auth.getSession();
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
            'apikey': publicAnonKey,
            'Authorization': `Bearer ${session.access_token}`,
          },
          body: JSON.stringify({
            caseIds: Array.from(selectedCases)
          }),
        }
      );

      if (response.ok) {
        const data = await response.json();
        
        // Download as JSON
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `phishing-cases-export-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        window.URL.revokeObjectURL(url);

        alert(`Successfully exported ${data.totalCases} cases`);
        setSelectedCases(new Set());
      } else {
        alert('Failed to export cases');
      }
    } catch (error) {
      console.error('Error exporting cases:', error);
      alert('Error exporting cases');
    }
  };

  const getMonthlyChartData = () => {
    if (!statistics) return [];

    return Object.entries(statistics.monthlyStats)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([month, data], index) => ({
        id: `${month}-${index}`,
        month: month.substr(5, 2) + '/' + month.substr(0, 4),
        'Total Scans': data.total,
        'High Risk': data.highRisk,
      }));
  };

  const getPieChartData = () => {
    if (!statistics) return [];
    return [
      { name: 'Safe', value: statistics.safeDetected, color: '#22c55e' },
      { name: 'Phishing', value: statistics.phishingDetected, color: '#ef4444' },
    ];
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="text-center">
          <Shield className="w-12 h-12 text-indigo-600 animate-pulse mx-auto mb-4" />
          <p className="text-gray-600">Loading admin dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <Shield className="w-10 h-10 text-indigo-600" />
            <div>
              <h1>Admin Dashboard</h1>
              <p className="text-gray-600">System-wide monitoring and analytics</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
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

        {/* Global Statistics Overview */}
        <div className="grid gap-6 md:grid-cols-4 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{statistics?.totalScans || 0}</div>
              <p className="text-xs text-muted-foreground">
                All users combined
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Phishing Detected</CardTitle>
              <AlertTriangle className="h-4 w-4 text-red-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">
                {statistics?.phishingDetected || 0}
              </div>
              <p className="text-xs text-muted-foreground">
                {statistics?.phishingRate || 0}% detection rate
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Unique Users</CardTitle>
              <Users className="h-4 w-4 text-blue-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">
                {statistics?.uniqueUsers || 0}
              </div>
              <p className="text-xs text-muted-foreground">
                {statistics?.anonymousScans || 0} anonymous scans
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Avg Risk Score</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{statistics?.avgRiskScore || 0}</div>
              <p className="text-xs text-muted-foreground">
                Out of 100
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Main Content Tabs */}
        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="logs">Scan Logs</TabsTrigger>
            <TabsTrigger value="analysis">Threat Analysis</TabsTrigger>
            <TabsTrigger value="export">Export Cases</TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-6">
            <div className="grid gap-6 md:grid-cols-2">
              {/* Detection Distribution */}
              <Card>
                <CardHeader>
                  <CardTitle>Detection Distribution</CardTitle>
                  <CardDescription>Safe vs Phishing websites</CardDescription>
                </CardHeader>
                <CardContent>
                  {statistics && statistics.totalScans > 0 ? (
                    <ResponsiveContainer width="100%" height={300}>
                      <PieChart>
                        <Pie
                          key="detection-pie"
                          data={getPieChartData()}
                          cx="50%"
                          cy="50%"
                          labelLine={false}
                          label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                          outerRadius={80}
                          fill="#8884d8"
                          dataKey="value"
                        >
                          {getPieChartData().map((entry) => (
                            <Cell key={`cell-${entry.name}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip key="pie-tooltip" />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-[300px] flex items-center justify-center text-gray-400">
                      No data available yet
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Monthly Trends */}
              <Card>
                <CardHeader>
                  <CardTitle>Monthly Scan Trends</CardTitle>
                  <CardDescription>High-risk URLs per month</CardDescription>
                </CardHeader>
                <CardContent>
                  {statistics && getMonthlyChartData().length > 0 ? (
                    <ResponsiveContainer width="100%" height={300}>
                      <LineChart data={getMonthlyChartData()}>
                        <CartesianGrid key="monthly-grid" strokeDasharray="3 3" />
                        <XAxis key="monthly-xaxis" dataKey="month" />
                        <YAxis key="monthly-yaxis" />
                        <Tooltip key="monthly-tooltip" />
                        <Legend key="monthly-legend" />
                        <Line key="total-scans-line" type="monotone" dataKey="Total Scans" stroke="#4f46e5" strokeWidth={2} dot={{ r: 4 }} />
                        <Line key="high-risk-line" type="monotone" dataKey="High Risk" stroke="#ef4444" strokeWidth={2} dot={{ r: 4 }} />
                      </LineChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-[300px] flex items-center justify-center text-gray-400">
                      No monthly data available yet
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Top Abused Domains */}
            <Card>
              <CardHeader>
                <CardTitle>Top Abused Domains</CardTitle>
                <CardDescription>Most frequently detected phishing domains</CardDescription>
              </CardHeader>
              <CardContent>
                {statistics && statistics.topAbusedDomains.length > 0 ? (
                  <div className="space-y-2">
                    {statistics.topAbusedDomains.map((domain, idx) => (
                      <div key={`${domain.domain}-${idx}`} className="flex items-center justify-between p-3 bg-red-50 rounded border border-red-200">
                        <span className="font-medium text-red-900">{domain.domain}</span>
                        <Badge variant="destructive">{domain.count} detections</Badge>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center text-gray-400 py-8">
                    No abused domains detected yet
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Scan Logs Tab with Filters */}
          <TabsContent value="logs">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Filter className="w-5 h-5" />
                  Search & Filter Scan Logs
                </CardTitle>
                <CardDescription>Filter detection records by date, risk level, domain, or user</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Filters */}
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
                  <div className="space-y-2">
                    <Label>Start Date</Label>
                    <Input
                      type="date"
                      value={startDate}
                      onChange={(e) => setStartDate(e.target.value)}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>End Date</Label>
                    <Input
                      type="date"
                      value={endDate}
                      onChange={(e) => setEndDate(e.target.value)}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Risk Level</Label>
                    <Select value={riskLevel} onValueChange={setRiskLevel}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Levels</SelectItem>
                        <SelectItem value="trusted">Trusted (0–19)</SelectItem>
                        <SelectItem value="low-risk">Low Risk (20–39)</SelectItem>
                        <SelectItem value="suspicious">Suspicious (40–59)</SelectItem>
                        <SelectItem value="high-risk">High Risk (60–79)</SelectItem>
                        <SelectItem value="critical">Critical (80–100)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label>Domain</Label>
                    <Input
                      placeholder="Filter by domain..."
                      value={domainFilter}
                      onChange={(e) => setDomainFilter(e.target.value)}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>User</Label>
                    <Input
                      placeholder="Filter by user..."
                      value={userFilter}
                      onChange={(e) => setUserFilter(e.target.value)}
                    />
                  </div>
                </div>

                <div className="flex items-center justify-between">
                  <p className="text-sm text-gray-600">
                    Showing {filteredDetections.length} of {detections.length} records
                  </p>
                  <Button variant="outline" size="sm" onClick={clearFilters}>
                    Clear Filters
                  </Button>
                </div>

                {/* Detection List */}
                {filteredDetections.length > 0 ? (
                  <ScrollArea className="h-[600px]">
                    <div className="space-y-3">
                      {filteredDetections.map((detection) => (
                        <Card key={detection.id} className="hover:shadow-md transition-shadow">
                          <CardContent className="pt-4">
                            <div className="flex items-start gap-4">
                              <div className="flex-1 space-y-2">
                                <div className="flex items-center gap-2 flex-wrap">
                                  {/* Result badge */}
                                  {detection.result ? (
                                    <Badge className={
                                      detection.riskScore >= 80 ? 'bg-red-900 text-white' :
                                      detection.riskScore >= 60 ? 'bg-red-500 text-white' :
                                      detection.riskScore >= 40 ? 'bg-yellow-500 text-white' :
                                      detection.riskScore >= 20 ? 'bg-blue-500 text-white' :
                                      'bg-green-600 text-white'
                                    }>
                                      {detection.result}
                                    </Badge>
                                  ) : detection.isPhishing ? (
                                    <Badge variant="destructive">
                                      <XCircle className="w-3 h-3 mr-1" />
                                      Phishing
                                    </Badge>
                                  ) : (
                                    <Badge className="bg-green-500">
                                      <CheckCircle className="w-3 h-3 mr-1" />
                                      Safe
                                    </Badge>
                                  )}
                                  {/* Decision badge */}
                                  {detection.decision && (
                                    <Badge variant="outline">{detection.decision}</Badge>
                                  )}
                                  <Badge variant="outline">
                                    Risk: {detection.riskScore}/100
                                  </Badge>
                                  <Badge variant="secondary">
                                    {detection.userId === 'anonymous' ? 'Anonymous' : detection.userEmail}
                                  </Badge>
                                </div>
                                <p className="text-sm font-medium break-all">{detection.url}</p>
                                <p className="text-xs text-gray-500">
                                  {new Date(detection.timestamp).toLocaleString()}
                                </p>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </ScrollArea>
                ) : (
                  <div className="h-[400px] flex items-center justify-center text-gray-400">
                    {detections.length === 0 
                      ? 'No detection records yet' 
                      : 'No records match your filters'}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Threat Analysis Tab */}
          <TabsContent value="analysis">
            <Card>
              <CardHeader>
                <CardTitle>Threat Intelligence Analysis</CardTitle>
                <CardDescription>Detailed breakdown of detected threats</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  {/* Risk Distribution */}
                  <div>
                    <h3 className="font-medium mb-4">Risk Score Distribution</h3>
                    <ResponsiveContainer width="100%" height={300}>
                      <BarChart
                        data={[
                          {
                            id: 'trusted',
                            name: 'Trusted (0–19)',
                            count: detections.filter(d => d != null && d.riskScore != null && d.riskScore < 20).length,
                          },
                          {
                            id: 'low-risk',
                            name: 'Low Risk (20–39)',
                            count: detections.filter(d => d != null && d.riskScore != null && d.riskScore >= 20 && d.riskScore < 40).length,
                          },
                          {
                            id: 'suspicious',
                            name: 'Suspicious (40–59)',
                            count: detections.filter(d => d != null && d.riskScore != null && d.riskScore >= 40 && d.riskScore < 60).length,
                          },
                          {
                            id: 'high-risk',
                            name: 'High Risk (60–79)',
                            count: detections.filter(d => d != null && d.riskScore != null && d.riskScore >= 60 && d.riskScore < 80).length,
                          },
                          {
                            id: 'critical',
                            name: 'Critical (80–100)',
                            count: detections.filter(d => d != null && d.riskScore != null && d.riskScore >= 80).length,
                          },
                        ]}
                      >
                        <CartesianGrid key="risk-grid" strokeDasharray="3 3" />
                        <XAxis key="risk-xaxis" dataKey="name" />
                        <YAxis key="risk-yaxis" />
                        <Tooltip key="risk-tooltip" />
                        <Bar key="risk-distribution-bar" dataKey="count" fill="#4f46e5" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>

                  {/* User Type Breakdown */}
                  <div className="grid gap-4 md:grid-cols-2">
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-base">User Source Breakdown</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2">
                          <div className="flex items-center justify-between p-2 bg-gray-50 rounded">
                            <span>Anonymous Users</span>
                            <Badge>{statistics?.anonymousScans || 0}</Badge>
                          </div>
                          <div className="flex items-center justify-between p-2 bg-gray-50 rounded">
                            <span>Registered Users</span>
                            <Badge>{(statistics?.totalScans || 0) - (statistics?.anonymousScans || 0)}</Badge>
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-base">Detection Summary</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2">
                          <div className="flex items-center justify-between p-2 bg-green-50 rounded">
                            <span>Safe URLs</span>
                            <Badge className="bg-green-500">{statistics?.safeDetected || 0}</Badge>
                          </div>
                          <div className="flex items-center justify-between p-2 bg-red-50 rounded">
                            <span>Phishing URLs</span>
                            <Badge variant="destructive">{statistics?.phishingDetected || 0}</Badge>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Export Cases Tab */}
          <TabsContent value="export">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Download className="w-5 h-5" />
                  Export Cases for Training & Awareness
                </CardTitle>
                <CardDescription>
                  Select cases to export (anonymized) for use in training materials, awareness slides, and incident reports
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex items-center justify-between bg-blue-50 p-4 rounded-lg border border-blue-200">
                  <div>
                    <p className="font-medium text-blue-900">
                      {selectedCases.size} case(s) selected
                    </p>
                    <p className="text-sm text-blue-700">
                      User identities will be anonymized in the export
                    </p>
                  </div>
                  <div className="flex gap-2">
                    {selectedCases.size > 0 && (
                      <Button variant="outline" onClick={() => setSelectedCases(new Set())}>
                        Clear Selection
                      </Button>
                    )}
                    <Button onClick={exportSelectedCases} disabled={selectedCases.size === 0}>
                      <Download className="w-4 h-4 mr-2" />
                      Export Selected
                    </Button>
                  </div>
                </div>

                {/* Cases List for Selection */}
                {filteredDetections.length > 0 ? (
                  <ScrollArea className="h-[500px]">
                    <div className="space-y-3">
                      {filteredDetections.map((detection) => (
                        <Card 
                          key={detection.id} 
                          className={`cursor-pointer transition-all ${
                            selectedCases.has(detection.id) 
                              ? 'border-blue-500 bg-blue-50' 
                              : 'hover:shadow-md'
                          }`}
                          onClick={() => toggleCaseSelection(detection.id)}
                        >
                          <CardContent className="pt-4">
                            <div className="flex items-start gap-4">
                              <input
                                type="checkbox"
                                checked={selectedCases.has(detection.id)}
                                onChange={() => toggleCaseSelection(detection.id)}
                                className="mt-1"
                              />
                              <div className="flex-1 space-y-2">
                                <div className="flex items-center gap-2 flex-wrap">
                                  {detection.isPhishing ? (
                                    <Badge variant="destructive">
                                      <XCircle className="w-3 h-3 mr-1" />
                                      Phishing
                                    </Badge>
                                  ) : (
                                    <Badge className="bg-green-500">
                                      <CheckCircle className="w-3 h-3 mr-1" />
                                      Safe
                                    </Badge>
                                  )}
                                  <Badge variant="outline">
                                    Risk: {detection.riskScore}/100
                                  </Badge>
                                </div>
                                <p className="text-sm font-medium break-all">{detection.url}</p>
                                <p className="text-xs text-gray-500">
                                  {new Date(detection.timestamp).toLocaleString()}
                                </p>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </ScrollArea>
                ) : (
                  <div className="h-[400px] flex items-center justify-center text-gray-400">
                    No cases available for export
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}