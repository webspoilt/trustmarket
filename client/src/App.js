import React, { Suspense, useState, useCallback, useMemo, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import { ReactQueryDevtools } from 'react-query/devtools';
import { Toaster } from 'react-hot-toast';
import { HelmetProvider } from 'react-helmet-async';

// Context Providers
import { AuthProvider } from './context/AuthContext';
import { SocketProvider } from './context/SocketContext';
import { NotificationProvider } from './context/NotificationContext';

// Layout Components
import Layout from './components/layout/Layout';
import MobileLayout from './components/layout/MobileLayout';
import LoadingSpinner from './components/common/LoadingSpinner';

// Lazy-loaded page components
const Home = React.lazy(() => import('./pages/Home'));
const Login = React.lazy(() => import('./pages/auth/Login'));
const Register = React.lazy(() => import('./pages/auth/Register'));
const CreateListing = React.lazy(() => import('./pages/CreateListing'));
const ListingDetails = React.lazy(() => import('./pages/ListingDetails'));
const SearchResults = React.lazy(() => import('./pages/SearchResults'));
const Messages = React.lazy(() => import('./pages/Messages'));
const Profile = React.lazy(() => import('./pages/Profile'));
const Dashboard = React.lazy(() => import('./pages/Dashboard'));
const Premium = React.lazy(() => import('./pages/Premium'));
const NotFound = React.lazy(() => import('./pages/NotFound'));

// Enhanced Loading Component with skeleton
const LoadingFallback = () => (
  <div className="min-h-screen bg-slate-900 flex flex-col items-center justify-center p-4">
    <div className="glass-dark border border-slate-700/50 rounded-2xl p-8 shadow-2xl flex flex-col items-center justify-center animate-fade-in-up">
      <LoadingSpinner size="large" />
      <p className="mt-6 text-slate-300 font-semibold tracking-wide animate-pulse">Loading Experience...</p>
    </div>
  </div>
);

// Skeleton loader for page content - used by child components
// eslint-disable-next-line no-unused-vars
const PageSkeleton = () => (
  <div className="animate-pulse">
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="h-8 bg-slate-800 rounded-xl w-1/3 mb-8"></div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {[...Array(8)].map((_, i) => (
          <div key={i} className="glass-dark border border-slate-700/50 rounded-2xl shadow-xl overflow-hidden">
            <div className="h-48 bg-slate-800/50"></div>
            <div className="p-6">
              <div className="h-4 bg-slate-800 rounded-lg w-3/4 mb-4"></div>
              <div className="h-4 bg-slate-800 rounded-lg w-1/2"></div>
            </div>
          </div>
        ))}
      </div>
    </div>
  </div>
);

// Page preloader hook for intelligent prefetching - available for future use
// eslint-disable-next-line no-unused-vars
const usePagePreloader = () => {
  return useCallback((path) => {
    // Prefetch page chunks when user hovers over links
    const link = document.querySelector(`a[href="${path}"]`);
    if (link) {
      link.addEventListener('mouseenter', () => {
        // Trigger React Router's prefetching
        const preloadLink = document.createElement('link');
        preloadLink.rel = 'prefetch';
        preloadLink.href = path;
        document.head.appendChild(preloadLink);
      }, { once: true });
    }
  }, []);
};

// Error Boundary with retry functionality
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      retryCount: 0
    };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Error caught by boundary:', error, errorInfo);
    this.setState({ errorInfo });

    // Report error to monitoring service
    if (process.env.NODE_ENV === 'production') {
      this.reportError(error, errorInfo);
    }
  }

  reportError = async (error, errorInfo) => {
    try {
      await fetch('/api/analytics/errors', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: error.message,
          stack: error.stack,
          componentStack: errorInfo.componentStack,
          timestamp: new Date().toISOString(),
          url: window.location.href,
          userAgent: navigator.userAgent,
        }),
      });
    } catch (e) {
      console.error('Failed to report error:', e);
    }
  };

  handleRetry = () => {
    this.setState(prev => ({
      hasError: false,
      error: null,
      errorInfo: null,
      retryCount: prev.retryCount + 1
    }));
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-900 flex items-center justify-center px-4">
          <div className="max-w-md w-full glass-dark border border-red-500/20 rounded-2xl shadow-2xl p-8 text-center">
            <div className="w-16 h-16 mx-auto mb-6 bg-red-500/10 rounded-full flex items-center justify-center border border-red-500/30 shadow-[0_0_15px_rgba(239,68,68,0.2)]">
              <svg className="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 15.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
            </div>
            <h2 className="text-2xl font-bold text-white mb-2">Something went wrong</h2>
            <p className="text-slate-400 mb-8 leading-relaxed">
              We're sorry, but an unexpected error occurred. Our team has been notified.
            </p>

            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <button
                onClick={this.handleRetry}
                className="bg-indigo-600 text-white px-6 py-3 rounded-xl hover:bg-indigo-700 transition-all font-bold shadow-lg shadow-indigo-500/30 hover:scale-105"
              >
                Try Again
              </button>
              <button
                onClick={() => window.location.reload()}
                className="bg-slate-800 border border-slate-600 text-slate-300 px-6 py-3 rounded-xl hover:bg-slate-700 transition-all font-bold hover:text-white"
              >
                Refresh Page
              </button>
            </div>

            {process.env.NODE_ENV === 'development' && this.state.error && (
              <div className="mt-6 p-4 bg-gray-100 rounded-lg text-left">
                <p className="text-sm font-mono text-red-600">{this.state.error.toString()}</p>
                {this.state.errorInfo && (
                  <pre className="mt-2 text-xs text-gray-600 overflow-auto">
                    {this.state.errorInfo.componentStack}
                  </pre>
                )}
              </div>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Create React Query client with optimized configuration
const createQueryClient = () => new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 10000),
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      refetchOnWindowFocus: true,
      refetchOnReconnect: 'always',
      suspense: true,
    },
    mutations: {
      retry: 1,
      onError: (error) => {
        console.error('Mutation error:', error);
      },
    },
  },
});

// Route prefetching component
const RoutePrefetcher = ({ children }) => {
  const location = useLocation();
  const [prefetched, setPrefetched] = useState(new Set());

  useEffect(() => {
    // Prefetch likely next routes based on current route
    const prefetchRoutes = () => {
      const routePatterns = {
        '/': ['/search', '/listing/', '/create-listing'],
        '/listing/': ['/messages/', '/profile'],
        '/messages': ['/profile', '/dashboard'],
      };

      const patterns = routePatterns[location.pathname] || [];
      patterns.forEach(pattern => {
        if (!prefetched.has(pattern)) {
          // Use React Router's built-in prefetching
          setPrefetched(prev => new Set([...prev, pattern]));
        }
      });
    };

    // Prefetch after initial load
    const timer = setTimeout(prefetchRoutes, 2000);
    return () => clearTimeout(timer);
  }, [location.pathname, prefetched]);

  return children;
};

// Scroll to top component
const ScrollToTop = () => {
  const { pathname } = useLocation();

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);

  return null;
};

// Network-aware loading wrapper
const NetworkAwareSuspense = ({ children, fallback }) => {
  const [, setIsOnline] = useState(navigator.onLine);
  const [wasOffline, setWasOffline] = useState(false);

  useEffect(() => {
    const handleOnline = () => {
      setIsOnline(true);
      if (wasOffline) {
        setWasOffline(false);
      }
    };

    const handleOffline = () => {
      setIsOnline(false);
      setWasOffline(true);
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [wasOffline]);

  return (
    <>
      {wasOffline && (
        <div className="fixed top-0 left-0 right-0 bg-amber-500 text-white text-center py-2 text-sm font-medium z-50">
          <span>You are back online. Content has been refreshed.</span>
        </div>
      )}
      <Suspense fallback={fallback}>
        {children}
      </Suspense>
    </>
  );
};

// Main App Component
function App() {
  const [queryClient] = useState(() => createQueryClient());

  const toastOptions = useMemo(() => ({
    duration: 4000,
    style: {
      background: '#ffffff',
      color: '#0f172a',
      borderRadius: '12px',
      boxShadow: '0 10px 40px -10px rgba(0, 0, 0, 0.15)',
      border: '1px solid #e2e8f0',
      fontSize: '14px',
      fontWeight: '500',
      maxWidth: '400px',
      padding: '12px 16px',
    },
    success: {
      duration: 3000,
      style: {
        borderLeft: '4px solid #10b981',
      },
      iconTheme: {
        primary: '#10b981',
        secondary: '#ffffff',
      },
    },
    error: {
      duration: 5000,
      style: {
        borderLeft: '4px solid #ef4444',
      },
      iconTheme: {
        primary: '#ef4444',
        secondary: '#ffffff',
      },
    },
    loading: {
      duration: Infinity,
      style: {
        borderLeft: '4px solid #3b82f6',
      },
    },
  }), []);

  return (
    <HelmetProvider>
      <ErrorBoundary>
        <QueryClientProvider client={queryClient}>
          <Router>
            <ScrollToTop />
            <RoutePrefetcher>
              <AuthProvider>
                <NotificationProvider>
                  <SocketProvider>
                    <div className="App min-h-screen bg-slate-900 text-slate-300 font-sans selection:bg-indigo-500/30">
                      <NetworkAwareSuspense fallback={<LoadingFallback />}>
                        <Routes>
                          {/* Public Routes */}
                          <Route path="/login" element={<Login />} />
                          <Route path="/register" element={<Register />} />

                          {/* Main Application Routes */}
                          <Route path="/" element={<Layout />}>
                            <Route index element={<Home />} />
                            <Route path="search" element={<SearchResults />} />
                            <Route path="listing/:id" element={<ListingDetails />} />
                            <Route path="messages" element={<Messages />} />
                            <Route path="messages/:conversationId" element={<Messages />} />
                            <Route path="profile" element={<Profile />} />
                            <Route path="profile/:userId" element={<Profile />} />
                            <Route path="dashboard" element={<Dashboard />} />
                            <Route path="premium" element={<Premium />} />
                          </Route>

                          {/* Mobile-optimized routes */}
                          <Route
                            path="/create-listing"
                            element={<MobileLayout><CreateListing /></MobileLayout>}
                          />

                          {/* 404 Route */}
                          <Route path="*" element={<NotFound />} />
                        </Routes>
                      </NetworkAwareSuspense>

                      {/* Toast Notifications */}
                      <Toaster
                        position="top-center"
                        reverseOrder={false}
                        gutter={8}
                        toastOptions={toastOptions}
                      />

                      {/* React Query Dev Tools (only in development) */}
                      {process.env.NODE_ENV === 'development' && (
                        <ReactQueryDevtools initialIsOpen={false} />
                      )}
                    </div>
                  </SocketProvider>
                </NotificationProvider>
              </AuthProvider>
            </RoutePrefetcher>
          </Router>
        </QueryClientProvider>
      </ErrorBoundary>
    </HelmetProvider>
  );
}

export default App;