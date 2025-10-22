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
    sm: 'h-4 w-4',
    md: 'h-8 w-8',
    lg: 'h-12 w-12',
  };

  return (
    <div className="flex items-center justify-center py-12">
      <div className="flex flex-col items-center space-y-4">
        <div className={`animate-spin rounded-full border-b-2 border-vt-primary ${sizeClasses[size]}`}></div>
        {text && (
          <span className="text-vt-muted text-sm">{text}</span>
        )}
      </div>
    </div>
  );
};

export default LoadingSpinner;
