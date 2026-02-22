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
        {/* Outer glowing ring */}
        <div className="absolute inset-0 rounded-full border-4 border-slate-700/30 opacity-50 shadow-[0_0_15px_rgba(99,102,241,0.2)]"></div>
        {/* Smooth spinning gradient ring */}
        <div className="absolute inset-0 rounded-full border-4 border-transparent border-t-indigo-500 border-r-fuchsia-500 animate-[spin_1s_cubic-bezier(0.4,0,0.2,1)_infinite]"></div>
        {/* Inner glassmorphic pulse */}
        {size === 'large' && (
          <div className="absolute inset-3 rounded-full bg-gradient-to-tr from-indigo-500/30 to-fuchsia-500/30 backdrop-blur-md animate-[pulse_2s_ease-in-out_infinite] shadow-inner"></div>
        )}
      </div>
      {text && (
        <p className="mt-6 text-indigo-300 font-semibold tracking-wide animate-[pulse_2s_ease-in-out_infinite] text-sm drop-shadow-md">{text}</p>
      )}
    </div>
  );
};

export default LoadingSpinner;