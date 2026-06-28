import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Alert, AlertDescription } from './ui/alert';
import { Brain, CheckCircle, XCircle, AlertCircle, Loader2, ArrowLeft } from 'lucide-react';
import { Textarea } from './ui/textarea';

interface AIModelConfigProps {
  accessToken: string;
  onDetectionComplete?: (result: any) => void;
  onBack?: () => void;
}

const PHISHGUARD_API = 'https://a206197xiatianzephishguard-api.onrender.com/predict';

export function AIModelConfig({ accessToken, onDetectionComplete, onBack }: AIModelConfigProps) {
  const [testUrl, setTestUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');

  const handleTestDetection = async () => {
    if (!testUrl) {
      setError('Please enter a URL to test');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const { projectId, publicAnonKey } = await import('../../../utils/supabase/info');

      const response = await fetch(
        `https://${projectId}.supabase.co/functions/v1/make-server-358bdfd0/ai-detect`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'apikey': publicAnonKey,
            'Authorization': `Bearer ${accessToken}`,
          },
          body: JSON.stringify({
            url: testUrl,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        const detail = data.details ? ` — ${data.details}` : '';
        setError((data.error || 'Failed to call AI API') + detail);
        setLoading(false);
        return;
      }

      setResult(data);

      if (onDetectionComplete) {
        onDetectionComplete(data);
      }
    } catch (err) {
      console.error('Detection error:', err);
      setError('An error occurred while calling the AI model');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-50 via-blue-50 to-pink-50 p-8">
      <div className="max-w-4xl mx-auto space-y-6">
        {onBack && (
          <Button onClick={onBack} variant="outline" className="gap-2">
            <ArrowLeft className="w-4 h-4" />
            Back to Detector
          </Button>
        )}
        <Card className="shadow-xl border-2 border-purple-200">
          <CardHeader className="bg-gradient-to-r from-purple-600 to-blue-600 text-white">
            <div className="flex items-center gap-3">
              <Brain className="w-8 h-8" />
              <div>
                <CardTitle className="text-2xl">AI Model Integration</CardTitle>
                <CardDescription className="text-purple-100">
                  Connect your trained AI model for phishing detection
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent className="mt-6 space-y-6">
            {/* API Configuration */}
            <div className="space-y-4">
              <div>
                <Label htmlFor="api-endpoint" className="text-base font-semibold">
                  AI API Endpoint *
                </Label>
                <p className="text-sm text-gray-600 mb-2">
                  The URL of your trained AI model API (e.g., https://your-api.com/predict)
                </p>
                <Input
                  id="api-endpoint"
                  type="url"
                  value={PHISHGUARD_API}
                  disabled
                  className="font-mono"
                />
              </div>
            </div>

            {/* API Format Info */}
            <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
              <h3 className="font-semibold text-blue-900 mb-2">Expected API Format</h3>
              <p className="text-sm text-blue-800 mb-3">
                Your AI API should accept POST requests with the following format:
              </p>
              <div className="bg-white p-3 rounded border border-blue-300">
                <p className="text-xs font-mono text-gray-800">
                  <strong>Request:</strong>
                </p>
                <pre className="text-xs text-gray-700 mt-1">
{`POST {your-api-endpoint}
Content-Type: application/json
Authorization: Bearer {api-key}

{
  "url": "https://example.com"
}`}
                </pre>
              </div>
              <div className="bg-white p-3 rounded border border-blue-300 mt-2">
                <p className="text-xs font-mono text-gray-800">
                  <strong>Response (example):</strong>
                </p>
                <pre className="text-xs text-gray-700 mt-1">
{`{
  "is_phishing": true,
  "confidence": 0.95,
  "risk_score": 87
}`}
                </pre>
              </div>
            </div>

            {/* Test Section */}
            <div className="border-t pt-6">
              <h3 className="text-lg font-semibold mb-4">Test Your AI Model</h3>

              <div className="space-y-4">
                <div>
                  <Label htmlFor="test-url">Test URL</Label>
                  <Input
                    id="test-url"
                    type="url"
                    placeholder="https://example.com"
                    value={testUrl}
                    onChange={(e) => setTestUrl(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleTestDetection()}
                  />
                </div>

                <Button
                  onClick={handleTestDetection}
                  disabled={loading || !testUrl}
                  className="w-full"
                  size="lg"
                >
                  {loading ? (
                    <>
                      <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                      Calling AI Model...
                    </>
                  ) : (
                    <>
                      <Brain className="w-5 h-5 mr-2" />
                      Test Detection
                    </>
                  )}
                </Button>
              </div>

              {/* Error Display */}
              {error && (
                <Alert variant="destructive" className="mt-4">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              {/* Result Display */}
              {result && (
                <div className="mt-6 space-y-4">
                  <div className="flex items-center gap-2">
                    <CheckCircle className="w-6 h-6 text-green-600" />
                    <h4 className="text-lg font-semibold text-green-900">
                      AI Model Response Received
                    </h4>
                  </div>

                  <Card className="bg-gradient-to-br from-green-50 to-blue-50 border-green-200">
                    <CardContent className="pt-6">
                      <div className="space-y-3">
                        <div>
                          <p className="text-sm text-gray-600">Tested URL:</p>
                          <p className="font-mono text-sm break-all">{result.url}</p>
                        </div>

                        <div>
                          <p className="text-sm text-gray-600">API Response:</p>
                          <div className="bg-white p-4 rounded border mt-2">
                            <pre className="text-xs overflow-x-auto">
                              {JSON.stringify(result.prediction, null, 2)}
                            </pre>
                          </div>
                        </div>

                        <div>
                          <p className="text-sm text-gray-600">Timestamp:</p>
                          <p className="text-sm">{new Date(result.timestamp).toLocaleString()}</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Integration Guide */}
        <Card>
          <CardHeader>
            <CardTitle>Integration Guide</CardTitle>
            <CardDescription>How to integrate your AI model</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <h4 className="font-semibold mb-2">1. Deploy Your AI Model</h4>
              <p className="text-sm text-gray-600">
                Deploy your trained phishing detection model as a REST API. Popular options include:
                FastAPI, Flask, Django REST Framework, or cloud platforms like AWS Lambda, Google Cloud Functions.
              </p>
            </div>

            <div>
              <h4 className="font-semibold mb-2">2. Configure the Endpoint</h4>
              <p className="text-sm text-gray-600">
                Enter your API endpoint URL above. The system will send POST requests with the URL to check.
              </p>
            </div>

            <div>
              <h4 className="font-semibold mb-2">3. Test the Integration</h4>
              <p className="text-sm text-gray-600">
                Use the test form above to verify your API is responding correctly before using it in production.
              </p>
            </div>

            <div>
              <h4 className="font-semibold mb-2">4. Use in Detection Flow</h4>
              <p className="text-sm text-gray-600">
                Once configured and tested, you can use this AI endpoint in the main phishing detection workflow.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
