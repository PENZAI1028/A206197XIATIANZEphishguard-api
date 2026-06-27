import { useEffect, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { Badge } from './ui/badge';
import { ScrollArea } from './ui/scroll-area';
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line } from 'recharts';
import { Shield, TrendingUp, Activity, AlertTriangle, CheckCircle, XCircle, LogOut, User } from 'lucide-react';

interface Statistics {
  totalScans: number;
  phishingDetected: number;
  safeDetected: number;
  avgRiskScore: number;
  recentScans: number;
  phishingRate: number;
  featureStats: {
    [key: string]: { safe: number; warning: number; danger: number };
  };
}

interface Detection {
  url: string;
  riskScore: number;
  isPhishing: boolean;
  timestamp: string;
  features: any;
}

interface DashboardProps {
  accessToken: string;
  userEmail: string;
  userName: string;
  onLogout: () => void;
  onBackToDetector?: () => void;
}

export function Dashboard({ accessToken, userEmail, userName, onLogout, onBackToDetector }: DashboardProps) {
  const [statistics, setStatistics] = useState<Statistics | null>(null);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const { projectId, publicAnonKey } = await import('../../../utils/supabase/info');

      // Fetch statistics
      const statsResponse = await fetch(
        `https://${projectId}.supabase.co/functions/v1/make-server-358bdfd0/statistics`,
        {
          headers: {
            'apikey': publicAnonKey,
            'Authorization': `Bearer ${accessToken}`,
          },
        }
      );

      if (statsResponse.ok) {
        const statsData = await statsResponse.json();
        setStatistics(statsData);
      }

      // Fetch detection history
      const detectionsResponse = await fetch(
        `https://${projectId}.supabase.co/functions/v1/make-server-358bdfd0/detections`,
        {
          headers: {
            'apikey': publicAnonKey,
            'Authorization': `Bearer ${accessToken}`,
          },
        }
      );

      if (detectionsResponse.ok) {
        const detectionsData = await detectionsResponse.json();
        setDetections(detectionsData.detections || []);
      }
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getPieChartData = () => {
    if (!statistics) return [];
    return [
      { name: 'Safe', value: statistics.safeDetected, color: '#22c55e' },
      { name: 'Phishing', value: statistics.phishingDetected, color: '#ef4444' },
    ];
  };

  const getFeatureChartData = () => {
    if (!statistics) return [];
    
    return Object.entries(statistics.featureStats).map(([key, value]) => ({
      name: key.replace(/([A-Z])/g, ' $1').trim(),
      Safe: value.safe,
      Warning: value.warning,
      Danger: value.danger,
    }));
  };

  const getRiskTrendData = () => {
    if (detections.length === 0) return [];
    
    // Group by date and calculate average risk score
    const dateMap = new Map<string, { total: number; count: number }>();
    
    detections.forEach(detection => {
      const date = new Date(detection.timestamp).toLocaleDateString();
      const existing = dateMap.get(date) || { total: 0, count: 0 };
      dateMap.set(date, {
        total: existing.total + detection.riskScore,
        count: existing.count + 1,
      });
    });

    return Array.from(dateMap.entries())
      .map(([date, { total, count }]) => ({
        date,
        avgRisk: Math.round(total / count),
      }))
      .slice(-7); // Last 7 days
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="text-center">
          <Shield className="w-12 h-12 text-indigo-600 animate-pulse mx-auto mb-4" />
          <p className="text-gray-600">Loading dashboard...</p>
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
              <h1>Detection Dashboard</h1>
              <p className="text-gray-600">Welcome back, {userName}</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className="text-sm text-gray-500">{userEmail}</p>
            </div>
            <Button variant="outline" onClick={onLogout}>
              <LogOut className="w-4 h-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>

        {/* Statistics Overview */}
        <div className="grid gap-6 md:grid-cols-4 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{statistics?.totalScans || 0}</div>
              <p className="text-xs text-muted-foreground">
                {statistics?.recentScans || 0} in last 7 days
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
                {statistics?.phishingRate || 0}% of total scans
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Safe Websites</CardTitle>
              <CheckCircle className="h-4 w-4 text-green-500" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">
                {statistics?.safeDetected || 0}
              </div>
              <p className="text-xs text-muted-foreground">
                {100 - (statistics?.phishingRate || 0)}% of total scans
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

        {/* Charts and Data */}
        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="history">Detection History</TabsTrigger>
            <TabsTrigger value="features">Feature Analysis</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <div className="grid gap-6 md:grid-cols-2">
              {/* Pie Chart */}
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
                          data={getPieChartData()}
                          cx="50%"
                          cy="50%"
                          labelLine={false}
                          label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                          outerRadius={80}
                          fill="#8884d8"
                          dataKey="value"
                        >
                          {getPieChartData().map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-[300px] flex items-center justify-center text-gray-400">
                      No data available yet
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Risk Trend */}
              <Card>
                <CardHeader>
                  <CardTitle>Risk Score Trend</CardTitle>
                  <CardDescription>Average risk score over time</CardDescription>
                </CardHeader>
                <CardContent>
                  {getRiskTrendData().length > 0 ? (
                    <ResponsiveContainer width="100%" height={300}>
                      <LineChart data={getRiskTrendData()}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="date" />
                        <YAxis domain={[0, 100]} />
                        <Tooltip />
                        <Legend />
                        <Line type="monotone" dataKey="avgRisk" stroke="#4f46e5" strokeWidth={2} name="Avg Risk Score" />
                      </LineChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-[300px] flex items-center justify-center text-gray-400">
                      No data available yet
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="history">
            <Card>
              <CardHeader>
                <CardTitle>Detection History</CardTitle>
                <CardDescription>Recent URL scans and their results</CardDescription>
              </CardHeader>
              <CardContent>
                {detections.length > 0 ? (
                  <ScrollArea className="h-[500px]">
                    <div className="space-y-4">
                      {detections.map((detection, idx) => (
                        <Card key={idx}>
                          <CardContent className="pt-6">
                            <div className="flex items-start justify-between">
                              <div className="flex-1 space-y-2">
                                <div className="flex items-center gap-2">
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
                  <div className="h-[500px] flex items-center justify-center text-gray-400">
                    No detection history yet. Start scanning URLs to see results here.
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="features">
            <Card>
              <CardHeader>
                <CardTitle>Feature Analysis</CardTitle>
                <CardDescription>Distribution of feature detection results</CardDescription>
              </CardHeader>
              <CardContent>
                {statistics && statistics.totalScans > 0 ? (
                  <ResponsiveContainer width="100%" height={400}>
                    <BarChart data={getFeatureChartData()}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} />
                      <YAxis />
                      <Tooltip />
                      <Legend />
                      <Bar dataKey="Safe" stackId="a" fill="#22c55e" />
                      <Bar dataKey="Warning" stackId="a" fill="#eab308" />
                      <Bar dataKey="Danger" stackId="a" fill="#ef4444" />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-[400px] flex items-center justify-center text-gray-400">
                    No data available yet
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