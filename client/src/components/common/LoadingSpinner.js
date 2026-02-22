import React from 'react';

const LoadingSpinner = ({ size = 'large', text = 'Loading...' }) => {
  const dimensions = {
    small: 'w-6 h-6',
    medium: 'w-8 h-8',
    large: 'w-16 h-16'
  };

  return (
    <div className="flex flex-col items-center justify-center p-8">
      <div className={`relative ${dimensions[size]}`}>
        {/* Outer ring */}
        <div className="absolute inset-0 rounded-full border-4 border-purple-200 opacity-25"></div>
        {/* Spinning ring */}
        <div className="absolute inset-0 rounded-full border-4 border-transparent border-t-indigo-600 border-r-purple-500 animate-spin"></div>
        {/* Inner glow */}
        {size === 'large' && (
          <div className="absolute inset-2 rounded-full bg-gradient-to-tr from-indigo-500/20 to-purple-500/20 animate-pulse"></div>
        )}
      </div>
      {text && (
        <p className="mt-4 text-slate-500 font-medium animate-pulse text-sm">{text}</p>
      )}
    </div>
  );
};

export default LoadingSpinner;