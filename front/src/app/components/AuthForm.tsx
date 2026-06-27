import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Alert, AlertDescription } from './ui/alert';
import { Shield, ArrowLeft, AlertCircle } from 'lucide-react';
import { PasswordInput } from './ui/password-input';

interface AuthFormProps {
  onLoginSuccess: (accessToken: string, email: string, name: string, role: string) => void;
  onSkipLogin?: () => void;
}

export function AuthForm({ onLoginSuccess, onSkipLogin }: AuthFormProps) {
  const [email, setEmail] = useState('a206197@siswa.ukm.edu.my');
  const [password, setPassword] = useState('Xyd20050801');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleLogin = async () => {
    if (!email || !password) {
      setError('Please enter both email and password');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const { getSupabaseClient } = await import('../../../utils/supabase/client');
      const supabase = getSupabaseClient();
      
      console.log('Attempting login for:', email);

      const { data, error: signInError } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (signInError) {
        console.log(`Error during admin login: ${signInError.message}`);
        setError(`Login failed: ${signInError.message}`);
        setLoading(false);
        return;
      }

      if (data.session && data.user) {
        console.log('Login successful, user metadata:', data.user.user_metadata);
        
        // Check if user is admin
        const role = data.user.user_metadata?.role;

        console.log('User role:', role);

        if (role !== 'admin') {
          setError('Access denied. This login is for administrators only.');
          await supabase.auth.signOut();
          setLoading(false);
          return;
        }

        const userName = data.user.user_metadata?.name || data.user.email?.split('@')[0] || 'Admin';
        console.log('Login success, redirecting...');
        onLoginSuccess(data.session.access_token, data.user.email || '', userName, role);
      }
    } catch (err) {
      console.error('Login error:', err);
      setError('An error occurred during login. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 flex items-center justify-center p-4">
      <Card className="w-full max-w-md shadow-xl">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <div className="bg-blue-600 p-4 rounded-full">
              <Shield className="w-12 h-12 text-white" />
            </div>
          </div>
          <CardTitle className="text-3xl">Administrator Login</CardTitle>
          <CardDescription className="text-base mt-2">
            Sign in to manage the phishing detection system
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {error && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="login-email">Email</Label>
                <Input
                  id="login-email"
                  type="email"
                  placeholder="admin@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="login-password">Password</Label>
                <PasswordInput
                  id="login-password"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
                />
              </div>

              <Button
                className="w-full"
                onClick={handleLogin}
                disabled={loading}
              >
                {loading ? 'Signing in...' : 'Sign In as Administrator'}
              </Button>
            </div>

          {/* Skip Login Button */}
          {onSkipLogin && (
            <div className="pt-4 border-t">
              <Button
                variant="outline"
                className="w-full"
                onClick={onSkipLogin}
              >
                <ArrowLeft className="w-4 h-4 mr-2" />
                Continue as Guest User
              </Button>
              <p className="text-sm text-gray-500 text-center mt-2">
                Use the phishing detection tool without logging in
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}