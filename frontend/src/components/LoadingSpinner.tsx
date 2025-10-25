import React from 'react';

interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  text?: string;
}

const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ 
  size = 'md', 
  text = 'Loading...' 
}) => {
  const sizeClasses = {
    sm: 'h-6 w-6',
    md: 'h-12 w-12',
    lg: 'h-16 w-16',
  };

  const dotSizes = {
    sm: 'h-2 w-2',
    md: 'h-3 w-3',
    lg: 'h-4 w-4',
  };

  return (
    <div className="flex items-center justify-center py-20">
      <div className="flex flex-col items-center space-y-6 animate-fade-in">
        {/* Animated gradient spinner */}
        <div className="relative">
          <div className={`${sizeClasses[size]} rounded-full border-4 border-vt-muted/20`}></div>
          <div className={`absolute inset-0 ${sizeClasses[size]} rounded-full border-4 border-transparent border-t-vt-primary border-r-vt-success animate-spin`}></div>
          <div className="absolute inset-0 flex items-center justify-center">
            <div className={`${dotSizes[size]} rounded-full bg-gradient-to-r from-vt-primary to-vt-success animate-pulse`}></div>
          </div>
        </div>

        {/* Loading text with pulsing dots */}
        {text && (
          <div className="flex items-center gap-2">
            <span className="text-vt-light font-medium">{text}</span>
            <div className="flex gap-1">
              <div className="w-1.5 h-1.5 bg-vt-primary rounded-full animate-pulse"></div>
              <div className="w-1.5 h-1.5 bg-vt-primary rounded-full animate-pulse" style={{ animationDelay: '0.2s' }}></div>
              <div className="w-1.5 h-1.5 bg-vt-primary rounded-full animate-pulse" style={{ animationDelay: '0.4s' }}></div>
            </div>
          </div>
        )}

        {/* Optional subtitle */}
        <p className="text-vt-muted text-sm">Please wait...</p>
      </div>
    </div>
  );
};

export default LoadingSpinner;
