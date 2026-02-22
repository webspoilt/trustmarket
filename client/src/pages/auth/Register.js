import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { apiService } from '../../services/api';
import Logo from '../../components/common/Logo';

const Register = () => {
  const [activeTab, setActiveTab] = useState('email'); // 'email' | 'phone'
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    phone: '',
    password: '',
    confirmPassword: ''
  });
  const [otp, setOtp] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [otpTimer, setOtpTimer] = useState(0);
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const navigate = useNavigate();
  const { register, googleLogin, otpLogin } = useAuth();

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
        document.getElementById('google-signup-btn'),
        {
          theme: 'outline',
          size: 'large',
          width: '100%',
          text: 'signup_with',
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
        setError(result.error || 'Google sign-up failed');
      }
    } catch {
      setError('Google sign-up failed. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [navigate]);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  // Email/Password register
  const handleEmailRegister = async (e) => {
    e.preventDefault();
    setError('');

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    if (formData.phone && !/^[6-9]\d{9}$/.test(formData.phone)) {
      setError('Please enter a valid 10-digit Indian mobile number');
      return;
    }

    setIsSubmitting(true);
    try {
      const result = await register({
        firstName: formData.firstName,
        lastName: formData.lastName,
        email: formData.email,
        phone: formData.phone,
        password: formData.password
      });
      if (result.success) {
        navigate('/');
      } else {
        setError(result.error || 'Registration failed.');
      }
    } catch {
      setError('An unexpected error occurred.');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Send OTP for phone registration
  const handleSendOtp = async () => {
    setError('');
    if (!/^[6-9]\d{9}$/.test(formData.phone)) {
      setError('Enter a valid 10-digit Indian mobile number');
      return;
    }
    setIsSubmitting(true);
    try {
      const response = await apiService.auth.otpSend(formData.phone);
      if (response.data.success) {
        setOtpSent(true);
        setOtpTimer(60);
        if (response.data.demoOtp) {
          setOtp(response.data.demoOtp);
        }
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to send OTP');
    } finally {
      setIsSubmitting(false);
    }
  };

  // Verify OTP for phone registration
  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);
    try {
      const result = await otpLogin(formData.phone, otp);
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
    `flex-1 py-3 text-sm font-bold rounded-lg transition-all ${activeTab === tab
      ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/30'
      : 'text-slate-400 hover:text-white hover:bg-slate-800'
    }`;

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-900 py-12 px-4 sm:px-6 lg:px-8 relative overflow-hidden">
      {/* Background decoration */}
      <div className="absolute top-1/4 right-1/4 w-96 h-96 bg-indigo-500/20 rounded-full blur-3xl -z-10 mix-blend-screen pointer-events-none"></div>
      <div className="absolute bottom-1/4 left-1/4 w-96 h-96 bg-fuchsia-500/20 rounded-full blur-3xl -z-10 mix-blend-screen pointer-events-none"></div>

      <div className="max-w-md w-full glass-dark border border-slate-700/50 p-8 rounded-2xl shadow-2xl relative z-10 space-y-8">
        <div className="mb-2">
          <Link to="/" className="flex justify-center mb-6 hover:scale-110 transition-transform duration-300">
            <Logo className="w-20 h-20" text={false} />
          </Link>
          <h2 className="text-center text-3xl font-extrabold text-white tracking-tight">
            Create your account
          </h2>
          <p className="mt-3 text-center text-sm text-slate-400 font-medium">
            Join India's safest <span className="text-indigo-400">P2P marketplace</span>
          </p>
        </div>

        {/* Google Sign-Up */}
        <div className="flex justify-center">
          <div id="google-signup-btn" className="w-full"></div>
        </div>

        {!process.env.REACT_APP_GOOGLE_CLIENT_ID && (
          <button
            disabled
            className="w-full flex items-center justify-center gap-3 py-3 px-4 border border-slate-600 rounded-xl shadow-sm bg-slate-800/50 text-sm font-medium text-slate-400 cursor-not-allowed"
          >
            <svg className="w-5 h-5 opacity-70" viewBox="0 0 24 24">
              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" />
              <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
              <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
              <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
            </svg>
            Google Sign-Up (set up GOOGLE_CLIENT_ID)
          </button>
        )}

        {/* Divider */}
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-slate-700"></div>
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-4 bg-slate-900 text-slate-400 font-medium">or register with</span>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex bg-slate-900 border border-slate-700/50 rounded-xl p-1.5 gap-1 shadow-inner">
          <button onClick={() => { setActiveTab('email'); setError(''); }} className={tabClass('email')}>
            Email & Password
          </button>
          <button onClick={() => { setActiveTab('phone'); setError(''); }} className={tabClass('phone')}>
            Phone & OTP
          </button>
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-lg relative text-sm font-medium" role="alert">
            {error}
          </div>
        )}

        {/* Email/Password Registration */}
        {activeTab === 'email' && (
          <form onSubmit={handleEmailRegister} className="space-y-5">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="firstName" className="block text-sm font-medium text-slate-300">First Name</label>
                <input id="firstName" name="firstName" type="text" required
                  className="mt-1 block w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all sm:text-sm"
                  placeholder="First name" value={formData.firstName} onChange={handleChange} />
              </div>
              <div>
                <label htmlFor="lastName" className="block text-sm font-medium text-slate-300">Last Name</label>
                <input id="lastName" name="lastName" type="text" required
                  className="mt-1 block w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all sm:text-sm"
                  placeholder="Last name" value={formData.lastName} onChange={handleChange} />
              </div>
            </div>
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-slate-300">Email Address</label>
              <input id="email" name="email" type="email" required autoComplete="email"
                className="mt-1 block w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all sm:text-sm"
                placeholder="you@example.com" value={formData.email} onChange={handleChange} />
            </div>
            <div>
              <label htmlFor="phone" className="block text-sm font-medium text-slate-300">Phone (optional)</label>
              <div className="mt-1 flex rounded-xl shadow-sm">
                <span className="inline-flex items-center px-4 text-sm text-slate-400 bg-slate-800 border border-r-0 border-slate-600 rounded-l-xl font-bold">+91</span>
                <input id="phone" name="phone" type="tel" maxLength={10}
                  className="block w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-r-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all sm:text-sm"
                  placeholder="10-digit number" value={formData.phone} onChange={handleChange} />
              </div>
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-slate-300">Password</label>
              <input id="password" name="password" type="password" required minLength={8} autoComplete="new-password"
                className="mt-1 block w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all sm:text-sm"
                placeholder="Min 8 chars, upper, lower & number" value={formData.password} onChange={handleChange} />
            </div>
            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-slate-300">Confirm Password</label>
              <input id="confirmPassword" name="confirmPassword" type="password" required autoComplete="new-password"
                className="mt-1 block w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all sm:text-sm"
                placeholder="Confirm password" value={formData.confirmPassword} onChange={handleChange} />
            </div>
            <button type="submit" disabled={isSubmitting}
              className="w-full flex justify-center py-3.5 px-4 rounded-xl shadow-lg shadow-indigo-500/30 text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-slate-900 focus:ring-indigo-500 disabled:opacity-50 transition-all hover:-translate-y-0.5"
            >
              {isSubmitting ? 'Creating Account...' : 'Create Account'}
            </button>
          </form>
        )}

        {/* Phone/OTP Registration */}
        {activeTab === 'phone' && (
          <form onSubmit={handleVerifyOtp} className="space-y-5">
            <div>
              <label htmlFor="reg-phone" className="block text-sm font-medium text-slate-300">Phone Number</label>
              <div className="mt-1 flex rounded-xl shadow-sm">
                <span className="inline-flex items-center px-4 text-sm text-slate-400 bg-slate-800 border border-r-0 border-slate-600 rounded-l-xl font-bold">+91</span>
                <input id="reg-phone" type="tel" required maxLength={10}
                  className="block w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-r-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all sm:text-sm"
                  placeholder="10-digit mobile number"
                  value={formData.phone}
                  onChange={(e) => setFormData({ ...formData, phone: e.target.value.replace(/\D/g, '') })}
                  disabled={otpSent}
                />
              </div>
              <p className="mt-2 text-xs text-slate-500 font-medium">We'll create your account and verify your number</p>
            </div>

            {!otpSent ? (
              <button type="button" onClick={handleSendOtp} disabled={isSubmitting}
                className="w-full flex justify-center py-3.5 px-4 rounded-xl shadow-lg shadow-indigo-500/30 text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-slate-900 focus:ring-indigo-500 disabled:opacity-50 transition-all hover:-translate-y-0.5"
              >
                {isSubmitting ? 'Sending SMS...' : 'Send Magic Link / OTP'}
              </button>
            ) : (
              <>
                <div className="animate-fade-in-up">
                  <label htmlFor="reg-otp" className="block text-sm font-medium text-slate-300">Enter Verification Code</label>
                  <input id="reg-otp" type="text" required maxLength={6}
                    className="mt-1 block w-full px-4 py-3 bg-slate-800 border border-slate-600 rounded-xl text-white placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent sm:text-lg text-center tracking-[1em] font-mono shadow-inner"
                    placeholder="------"
                    value={otp} onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))} autoFocus
                  />
                  <div className="mt-3 flex justify-between items-center text-xs text-slate-400 font-medium">
                    <span>Sent to +91 {formData.phone}</span>
                    {otpTimer > 0 ? (
                      <span className="text-indigo-400">Resend in {otpTimer}s</span>
                    ) : (
                      <button type="button" onClick={handleSendOtp} className="text-indigo-400 hover:text-indigo-300 transition-colors">Resend Code</button>
                    )}
                  </div>
                </div>
                <button type="submit" disabled={isSubmitting || otp.length < 6}
                  className="w-full flex justify-center py-3.5 px-4 rounded-xl shadow-lg shadow-indigo-500/30 text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-slate-900 focus:ring-indigo-500 disabled:opacity-50 transition-all hover:-translate-y-0.5"
                >
                  {isSubmitting ? 'Verifying...' : 'Verify & Create Account'}
                </button>
                <button type="button"
                  onClick={() => { setOtpSent(false); setOtp(''); setOtpTimer(0); }}
                  className="w-full text-sm font-medium text-slate-400 hover:text-slate-300 transition-colors"
                >
                  ← Change number
                </button>
              </>
            )}
          </form>
        )}

        <div className="text-center pt-2">
          <p className="text-sm font-medium text-slate-400">
            Already have an account?{' '}
            <Link to="/login" className="text-indigo-400 hover:text-indigo-300 hover:underline transition-colors">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Register;