import React from 'react';

export type ButtonVariant = 'primary' | 'success' | 'error' | 'warning' | 'secondary' | 'danger';
export type ButtonSize = 'sm' | 'md' | 'lg';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  fullWidth?: boolean;
  isLoading?: boolean;
  children: React.ReactNode;
}

const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  size = 'md',
  fullWidth = false,
  isLoading = false,
  disabled,
  className = '',
  children,
  ...props
}) => {
  const baseStyles = 'font-semibold rounded-lg transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-vt-dark disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 cursor-pointer';
  
  const variantStyles: Record<ButtonVariant, string> = {
    primary: 'bg-gradient-to-r from-vt-primary to-vt-primary/80 text-white border border-vt-primary/50 hover:from-vt-primary/90 hover:to-vt-primary/70 hover:border-vt-primary shadow-lg shadow-vt-primary/30 hover:shadow-xl hover:shadow-vt-primary/40 focus:ring-vt-primary',
    success: 'bg-gradient-to-r from-vt-success to-vt-success/80 text-white border border-vt-success/50 hover:from-vt-success/90 hover:to-vt-success/70 hover:border-vt-success shadow-lg shadow-vt-success/30 hover:shadow-xl hover:shadow-vt-success/40 focus:ring-vt-success',
    error: 'bg-gradient-to-r from-vt-error to-vt-error/80 text-white border border-vt-error/50 hover:from-vt-error/90 hover:to-vt-error/70 hover:border-vt-error shadow-lg shadow-vt-error/30 hover:shadow-xl hover:shadow-vt-error/40 focus:ring-vt-error',
    danger: 'bg-gradient-to-r from-red-600 to-red-500 text-white border border-red-500/50 hover:from-red-700 hover:to-red-600 hover:border-red-600 shadow-lg shadow-red-500/30 hover:shadow-xl hover:shadow-red-600/40 focus:ring-red-500',
    warning: 'bg-gradient-to-r from-vt-warning to-vt-warning/80 text-white border border-vt-warning/50 hover:from-vt-warning/90 hover:to-vt-warning/70 hover:border-vt-warning shadow-lg shadow-vt-warning/30 hover:shadow-xl hover:shadow-vt-warning/40 focus:ring-vt-warning',
    secondary: 'bg-vt-muted/10 text-vt-light border border-vt-muted/30 hover:bg-vt-muted/20 hover:border-vt-primary/40 shadow-md shadow-vt-muted/10 hover:shadow-lg hover:shadow-vt-primary/20 focus:ring-vt-primary',
  };
  
  const sizeStyles: Record<ButtonSize, string> = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2.5 text-sm',
    lg: 'px-6 py-3 text-base',
  };
  
  const widthStyle = fullWidth ? 'w-full' : '';
  
  return (
    <button
      className={`${baseStyles} ${variantStyles[variant]} ${sizeStyles[size]} ${widthStyle} ${className}`}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading ? (
        <>
          <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <span>Loading...</span>
        </>
      ) : (
        children
      )}
    </button>
  );
};

export default Button;

