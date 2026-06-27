import { useState, useEffect } from 'react';
import { AuthForm } from './components/AuthForm';
import { PhishingDetector } from './components/PhishingDetector';
import { AdminDashboard } from './components/AdminDashboard';
import { AIModelConfig } from './components/AIModelConfig';

type View = 'detector' | 'auth' | 'dashboard' | 'ai-config';

export default function App() {
  const [view, setView] = useState<View>('detector');
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [userEmail, setUserEmail] = useState<string>('');
  const [userName, setUserName] = useState<string>('');
  const [userRole, setUserRole] = useState<string>('');

  // Check for existing session on mount
  useEffect(() => {
    checkSession();
  }, []);

  const checkSession = async () => {
    try {
      const { getSupabaseClient } = await import('../../utils/supabase/client');
      const supabase = getSupabaseClient();

      const { data: { session } } = await supabase.auth.getSession();

      if (session?.access_token && session.user) {
        const role = session.user.user_metadata?.role || 'user';

        setAccessToken(session.access_token);
        setUserEmail(session.user.email || '');
        setUserName(session.user.user_metadata?.name || session.user.email?.split('@')[0] || 'User');
        setUserRole(role);

        // Auto-navigate to dashboard for admin
        if (role === 'admin') {
          setView('dashboard');
        }
      }
    } catch (error) {
      console.error('Error checking session:', error);
    }
  };

  const handleLoginSuccess = (token: string, email: string, name: string, role: string) => {
    setAccessToken(token);
    setUserEmail(email);
    setUserName(name);
    setUserRole(role);

    // Admin goes directly to dashboard
    if (role === 'admin') {
      setView('dashboard');
    } else {
      setView('detector');
    }
  };

  const handleLogout = async () => {
    try {
      const { getSupabaseClient } = await import('../../utils/supabase/client');
      const supabase = getSupabaseClient();

      await supabase.auth.signOut();
      
      setAccessToken(null);
      setUserEmail('');
      setUserName('');
      setUserRole('');
      setView('auth');
    } catch (error) {
      console.error('Error logging out:', error);
    }
  };

  if (view === 'auth') {
    return <AuthForm onLoginSuccess={handleLoginSuccess} onSkipLogin={() => setView('detector')} />;
  }

  if (view === 'dashboard') {
    return (
      <AdminDashboard
        accessToken={accessToken!}
        userEmail={userEmail}
        userName={userName}
        onLogout={handleLogout}
        onBackToDetector={() => setView('detector')}
      />
    );
  }

  if (view === 'ai-config') {
    return (
      <AIModelConfig
        onDetectionComplete={(result) => {
          console.log('AI Detection result:', result);
        }}
        onBack={() => setView('detector')}
      />
    );
  }

  return (
    <PhishingDetector
      accessToken={accessToken || undefined}
      onViewDashboard={accessToken ? () => setView('dashboard') : undefined}
      onLogin={!accessToken ? () => setView('auth') : undefined}
      onViewAIConfig={() => setView('ai-config')}
    />
  );
}