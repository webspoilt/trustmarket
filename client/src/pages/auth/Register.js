import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { apiService } from '../../services/api';

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
    `flex-1 py-2.5 text-sm font-medium rounded-md transition-all ${activeTab === tab
      ? 'bg-blue-600 text-white shadow-sm'
      : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'
    }`;

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-6">
        <div>
          <h2 className="text-center text-3xl font-extrabold text-gray-900">
            Create your account
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Join India's safest P2P marketplace
          </p>
        </div>

        {/* Google Sign-Up */}
        <div className="flex justify-center">
          <div id="google-signup-btn" className="w-full"></div>
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
            Google Sign-Up (set up GOOGLE_CLIENT_ID)
          </button>
        )}

        {/* Divider */}
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-300"></div>
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-4 bg-gray-50 text-gray-500">or register with</span>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex bg-gray-100 rounded-lg p-1 gap-1">
          <button onClick={() => { setActiveTab('email'); setError(''); }} className={tabClass('email')}>
            Email & Password
          </button>
          <button onClick={() => { setActiveTab('phone'); setError(''); }} className={tabClass('phone')}>
            Phone & OTP
          </button>
        </div>

        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded text-sm" role="alert">
            {error}
          </div>
        )}

        {/* Email/Password Registration */}
        {activeTab === 'email' && (
          <form onSubmit={handleEmailRegister} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="firstName" className="block text-sm font-medium text-gray-700">First Name</label>
                <input id="firstName" name="firstName" type="text" required
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="First name" value={formData.firstName} onChange={handleChange} />
              </div>
              <div>
                <label htmlFor="lastName" className="block text-sm font-medium text-gray-700">Last Name</label>
                <input id="lastName" name="lastName" type="text" required
                  className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="Last name" value={formData.lastName} onChange={handleChange} />
              </div>
            </div>
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">Email</label>
              <input id="email" name="email" type="email" required autoComplete="email"
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="you@example.com" value={formData.email} onChange={handleChange} />
            </div>
            <div>
              <label htmlFor="phone" className="block text-sm font-medium text-gray-700">Phone (optional)</label>
              <div className="mt-1 flex">
                <span className="inline-flex items-center px-3 text-sm text-gray-500 bg-gray-100 border border-r-0 border-gray-300 rounded-l-md">+91</span>
                <input id="phone" name="phone" type="tel" maxLength={10}
                  className="block w-full px-3 py-2 border border-gray-300 rounded-r-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="10-digit number" value={formData.phone} onChange={handleChange} />
              </div>
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">Password</label>
              <input id="password" name="password" type="password" required minLength={8} autoComplete="new-password"
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="Min 8 chars, upper, lower & number" value={formData.password} onChange={handleChange} />
            </div>
            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700">Confirm Password</label>
              <input id="confirmPassword" name="confirmPassword" type="password" required autoComplete="new-password"
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="Confirm password" value={formData.confirmPassword} onChange={handleChange} />
            </div>
            <button type="submit" disabled={isSubmitting}
              className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
            >
              {isSubmitting ? 'Creating Account...' : 'Create Account'}
            </button>
          </form>
        )}

        {/* Phone/OTP Registration */}
        {activeTab === 'phone' && (
          <form onSubmit={handleVerifyOtp} className="space-y-4">
            <div>
              <label htmlFor="reg-phone" className="block text-sm font-medium text-gray-700">Phone Number</label>
              <div className="mt-1 flex">
                <span className="inline-flex items-center px-3 text-sm text-gray-500 bg-gray-100 border border-r-0 border-gray-300 rounded-l-md">+91</span>
                <input id="reg-phone" type="tel" required maxLength={10}
                  className="block w-full px-3 py-2 border border-gray-300 rounded-r-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="10-digit mobile number"
                  value={formData.phone}
                  onChange={(e) => setFormData({ ...formData, phone: e.target.value.replace(/\D/g, '') })}
                  disabled={otpSent}
                />
              </div>
              <p className="mt-1 text-xs text-gray-500">We'll create your account and verify your number</p>
            </div>

            {!otpSent ? (
              <button type="button" onClick={handleSendOtp} disabled={isSubmitting}
                className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
              >
                {isSubmitting ? 'Sending...' : 'Send OTP'}
              </button>
            ) : (
              <>
                <div>
                  <label htmlFor="reg-otp" className="block text-sm font-medium text-gray-700">Enter OTP</label>
                  <input id="reg-otp" type="text" required maxLength={6}
                    className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm text-center tracking-[0.5em] text-lg font-mono"
                    placeholder="● ● ● ● ● ●"
                    value={otp} onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))} autoFocus
                  />
                  <div className="mt-2 flex justify-between items-center text-xs text-gray-500">
                    <span>OTP sent to +91 {formData.phone}</span>
                    {otpTimer > 0 ? (
                      <span>Resend in {otpTimer}s</span>
                    ) : (
                      <button type="button" onClick={handleSendOtp} className="text-blue-600 hover:underline font-medium">Resend OTP</button>
                    )}
                  </div>
                </div>
                <button type="submit" disabled={isSubmitting || otp.length < 6}
                  className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
                >
                  {isSubmitting ? 'Verifying...' : 'Verify & Create Account'}
                </button>
                <button type="button"
                  onClick={() => { setOtpSent(false); setOtp(''); setOtpTimer(0); }}
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
            Already have an account?{' '}
            <Link to="/login" className="font-medium text-blue-600 hover:text-blue-500">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Register;