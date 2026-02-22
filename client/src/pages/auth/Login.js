import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { apiService } from '../../services/api';

const Login = () => {
  const [activeTab, setActiveTab] = useState('email'); // 'email' | 'phone'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [phone, setPhone] = useState('');
  const [otp, setOtp] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [otpTimer, setOtpTimer] = useState(0);
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const navigate = useNavigate();
  const { login, googleLogin, otpLogin } = useAuth();

  // OTP countdown timer
  useEffect(() => {
    if (otpTimer > 0) {
      const interval = setInterval(() => setOtpTimer(t => t - 1), 1000);
      return () => clearInterval(interval);
    }
  }, [otpTimer]);

  // Load Google Sign-In script
  useEffect(() => {
    const clientId = process.env.REACT_APP_GOOGLE_CLIENT_ID;
    if (!clientId) return;

    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.onload = () => {
      window.google?.accounts.id.initialize({
        client_id: clientId,
        callback: handleGoogleResponse,
      });
      window.google?.accounts.id.renderButton(
        document.getElementById('google-signin-btn'),
        {
          theme: 'outline',
          size: 'large',
          width: '100%',
          text: 'signin_with',
          shape: 'rectangular',
        }
      );
    };
    document.body.appendChild(script);
    return () => {
      document.body.removeChild(script);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleGoogleResponse = useCallback(async (response) => {
    setError('');
    setIsSubmitting(true);
    try {
      const result = await googleLogin(response.credential);
      if (result.success) {
        navigate('/');
      } else {
        setError(result.error || 'Google sign-in failed');
      }
    } catch {
      setError('Google sign-in failed. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [navigate]);

  // Email/Password login
  const handleEmailLogin = async (e) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);
    try {
      const result = await login({ email, password });
      if (result.success) {
        navigate('/');
      } else {
        setError(result.error || 'Login failed. Please try again.');
      }
    } catch {
      setError('An unexpected error occurred.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Send OTP
  const handleSendOtp = async () => {
    setError('');
    if (!/^[6-9]\d{9}$/.test(phone)) {
      setError('Enter a valid 10-digit Indian mobile number');
      return;
    }
    setIsSubmitting(true);
    try {
      const response = await apiService.auth.otpSend(phone);
      if (response.data.success) {
        setOtpSent(true);
        setOtpTimer(60);
        if (response.data.demoOtp) {
          setOtp(response.data.demoOtp); // Auto-fill in dev mode
        }
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to send OTP');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Verify OTP
  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);
    try {
      const result = await otpLogin(phone, otp);
      if (result.success) {
        navigate('/');
      } else {
        setError(result.error || 'OTP verification failed');
      }
    } catch {
      setError('An unexpected error occurred.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const tabClass = (tab) =>
    `flex-1 py-2.5 text-sm font-medium rounded-md transition-all ${activeTab === tab
      ? 'bg-blue-600 text-white shadow-sm'
      : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'
    }`;

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-6">
        <div>
          <h2 className="text-center text-3xl font-extrabold text-gray-900">
            Sign in to your account
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Welcome back to TrustMarket
          </p>
        </div>

        {/* Google Sign-In */}
        <div className="flex justify-center">
          <div id="google-signin-btn" className="w-full"></div>
        </div>

        {!process.env.REACT_APP_GOOGLE_CLIENT_ID && (
          <button
            disabled
            className="w-full flex items-center justify-center gap-3 py-2.5 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 cursor-not-allowed"
          >
            <svg className="w-5 h-5" viewBox="0 0 24 24">
              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" />
              <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
              <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
              <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
            </svg>
            Google Sign-In (set up GOOGLE_CLIENT_ID)
          </button>
        )}

        {/* Divider */}
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-300"></div>
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-4 bg-gray-50 text-gray-500">or continue with</span>
          </div>
        </div>

        {/* Tabs: Email | Phone */}
        <div className="flex bg-gray-100 rounded-lg p-1 gap-1">
          <button onClick={() => { setActiveTab('email'); setError(''); }} className={tabClass('email')}>
            Email & Password
          </button>
          <button onClick={() => { setActiveTab('phone'); setError(''); }} className={tabClass('phone')}>
            Phone & OTP
          </button>
        </div>

        {/* Error display */}
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded relative text-sm" role="alert">
            {error}
          </div>
        )}

        {/* Email/Password Form */}
        {activeTab === 'email' && (
          <form onSubmit={handleEmailLogin} className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">Email</label>
              <input
                id="email" type="email" required autoComplete="email"
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="you@example.com"
                value={email} onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">Password</label>
              <input
                id="password" type="password" required autoComplete="current-password"
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="Enter your password"
                value={password} onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <button
              type="submit" disabled={isSubmitting}
              className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
            >
              {isSubmitting ? 'Signing in...' : 'Sign in'}
            </button>
          </form>
        )}

        {/* Phone/OTP Form */}
        {activeTab === 'phone' && (
          <form onSubmit={handleVerifyOtp} className="space-y-4">
            <div>
              <label htmlFor="phone" className="block text-sm font-medium text-gray-700">Phone Number</label>
              <div className="mt-1 flex">
                <span className="inline-flex items-center px-3 text-sm text-gray-500 bg-gray-100 border border-r-0 border-gray-300 rounded-l-md">
                  +91
                </span>
                <input
                  id="phone" type="tel" required maxLength={10}
                  className="block w-full px-3 py-2 border border-gray-300 rounded-r-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="10-digit mobile number"
                  value={phone} onChange={(e) => setPhone(e.target.value.replace(/\D/g, ''))}
                  disabled={otpSent}
                />
              </div>
            </div>

            {!otpSent ? (
              <button
                type="button" onClick={handleSendOtp} disabled={isSubmitting}
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
              >
                {isSubmitting ? 'Sending...' : 'Send OTP'}
              </button>
            ) : (
              <>
                <div>
                  <label htmlFor="otp" className="block text-sm font-medium text-gray-700">Enter OTP</label>
                  <input
                    id="otp" type="text" required maxLength={6}
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm text-center tracking-[0.5em] text-lg font-mono"
                    placeholder="● ● ● ● ● ●"
                    value={otp} onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))}
                    autoFocus
                  />
                  <div className="mt-2 flex justify-between items-center text-xs text-gray-500">
                    <span>OTP sent to +91 {phone}</span>
                    {otpTimer > 0 ? (
                      <span>Resend in {otpTimer}s</span>
                    ) : (
                      <button type="button" onClick={handleSendOtp} className="text-blue-600 hover:underline font-medium">
                        Resend OTP
                      </button>
                    )}
                  </div>
                </div>
                <button
                  type="submit" disabled={isSubmitting || otp.length < 6}
                  className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                >
                  {isSubmitting ? 'Verifying...' : 'Verify & Sign in'}
                </button>
                <button
                  type="button"
                  onClick={() => { setOtpSent(false); setOtp(''); setPhone(''); setOtpTimer(0); }}
                  className="w-full text-sm text-gray-500 hover:text-gray-700"
                >
                  ← Change phone number
                </button>
              </>
            )}
          </form>
        )}

        <div className="text-center">
          <p className="text-sm text-gray-600">
            Don't have an account?{' '}
            <Link to="/register" className="font-medium text-blue-600 hover:text-blue-500">
              Sign up
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;