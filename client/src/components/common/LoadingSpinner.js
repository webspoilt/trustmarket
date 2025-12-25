import React from 'react';

const LoadingSpinner = ({ 
  size = 'medium', 
  color = 'primary', 
  className = '',
  text = '',
  variant = 'spinner' // 'spinner', 'dots', 'pulse'
}) => {
  const sizeClasses = {
    small: 'w-4 h-4',
    medium: 'w-8 h-8',
    large: 'w-12 h-12',
    xlarge: 'w-16 h-16',
  };

  const colorClasses = {
    primary: 'border-primary-500',
    white: 'border-white',
    gray: 'border-gray-400',
    success: 'border-success',
    warning: 'border-warning',
    error: 'border-error',
  };

  const textSizeClasses = {
    small: 'text-xs',
    medium: 'text-sm',
    large: 'text-base',
    xlarge: 'text-lg',
  };

  const renderSpinner = () => (
    <div
      className={`
        ${sizeClasses[size]} 
        ${colorClasses[color]} 
        border-2 border-t-transparent 
        rounded-full 
        animate-spin
        ${className}
      `}
      role="status"
      aria-label="Loading"
    />
  );

  const renderDots = () => (
    <div className="flex space-x-1">
      <div
        className={`
          ${size === 'small' ? 'w-1 h-1' : size === 'medium' ? 'w-2 h-2' : 'w-3 h-3'}
          ${color === 'white' ? 'bg-white' : `bg-${color}-500`}
          rounded-full animate-pulse
        `}
        style={{ animationDelay: '0ms' }}
      />
      <div
        className={`
          ${size === 'small' ? 'w-1 h-1' : size === 'medium' ? 'w-2 h-2' : 'w-3 h-3'}
          ${color === 'white' ? 'bg-white' : `bg-${color}-500`}
          rounded-full animate-pulse
        `}
        style={{ animationDelay: '200ms' }}
      />
      <div
        className={`
          ${size === 'small' ? 'w-1 h-1' : size === 'medium' ? 'w-2 h-2' : 'w-3 h-3'}
          ${color === 'white' ? 'bg-white' : `bg-${color}-500`}
          rounded-full animate-pulse
        `}
        style={{ animationDelay: '400ms' }}
      />
    </div>
  );

  const renderPulse = () => (
    <div
      className={`
        ${sizeClasses[size]} 
        ${colorClasses[color]} 
        rounded-full 
        animate-pulse
        ${className}
      `}
    />
  );

  const renderContent = () => {
    switch (variant) {
      case 'dots':
        return renderDots();
      case 'pulse':
        return renderPulse();
      default:
        return renderSpinner();
    }
  };

  if (text) {
    return (
      <div className="flex flex-col items-center justify-center space-y-2">
        {renderContent()}
        {text && (
          <span className={`${textSizeClasses[size]} text-gray-600 font-medium`}>
            {text}
          </span>
        )}
      </div>
    );
  }

  return renderContent();
};

// Inline loading component for buttons
export const ButtonSpinner = ({ color = 'white' }) => (
  <div className="flex items-center">
    <div
      className={`
        w-4 h-4 
        ${color === 'white' ? 'border-white' : `border-${color}-500`} 
        border-2 border-t-transparent 
        rounded-full 
        animate-spin
      `}
    />
  </div>
);

// Loading overlay component
export const LoadingOverlay = ({ 
  isVisible, 
  text = 'Loading...', 
  className = '',
  backdrop = true 
}) => {
  if (!isVisible) return null;

  return (
    <div 
      className={`
        fixed inset-0 z-50 
        flex items-center justify-center
        ${backdrop ? 'bg-black bg-opacity-50' : ''}
        ${className}
      `}
    >
      <div className="bg-white rounded-lg p-6 shadow-xl">
        <LoadingSpinner size="large" text={text} />
      </div>
    </div>
  );
};

// Page loading component
export const PageLoader = ({ text = 'Loading...' }) => (
  <div className="min-h-screen flex items-center justify-center bg-gray-50">
    <div className="text-center">
      <LoadingSpinner size="xlarge" />
      <p className="mt-4 text-gray-600 font-medium">{text}</p>
    </div>
  </div>
);

// Skeleton loader component for content
export const SkeletonLoader = ({ 
  count = 1, 
  className = '',
  height = 'h-4',
  width = 'w-full'
}) => {
  return (
    <>
      {Array.from({ length: count }).map((_, index) => (
        <div
          key={index}
          className={`
            ${height} 
            ${width} 
            bg-gray-200 
            rounded 
            animate-pulse
            ${className}
          `}
        />
      ))}
    </>
  );
};

// Card skeleton loader
export const CardSkeleton = ({ showImage = true }) => (
  <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4 space-y-4">
    {showImage && (
      <div className="w-full h-48 bg-gray-200 rounded animate-pulse" />
    )}
    <div className="space-y-2">
      <SkeletonLoader height="h-6" />
      <SkeletonLoader height="h-4" width="w-3/4" />
    </div>
    <div className="flex justify-between items-center">
      <SkeletonLoader height="h-6" width="w-20" />
      <SkeletonLoader height="h-6" width="w-16" />
    </div>
  </div>
);

// List skeleton loader
export const ListSkeleton = ({ count = 3 }) => (
  <div className="space-y-4">
    {Array.from({ length: count }).map((_, index) => (
      <div key={index} className="flex items-center space-x-4 p-4 bg-white rounded-lg shadow-sm">
        <div className="w-12 h-12 bg-gray-200 rounded-full animate-pulse" />
        <div className="flex-1 space-y-2">
          <SkeletonLoader height="h-4" />
          <SkeletonLoader height="h-3" width="w-1/2" />
        </div>
        <SkeletonLoader height="h-8" width="w-20" />
      </div>
    ))}
  </div>
);

// Text skeleton loader
export const TextSkeleton = ({ lines = 3, className = '' }) => (
  <div className={`space-y-2 ${className}`}>
    {Array.from({ length: lines }).map((_, index) => (
      <SkeletonLoader
        key={index}
        height="h-4"
        width={index === lines - 1 ? 'w-3/4' : 'w-full'}
      />
    ))}
  </div>
);

// Image skeleton loader
export const ImageSkeleton = ({ width = 'w-full', height = 'h-48', className = '' }) => (
  <div className={`${width} ${height} bg-gray-200 rounded animate-pulse ${className}`} />
);

export default LoadingSpinner;