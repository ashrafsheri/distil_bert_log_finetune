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
  const baseStyles = 'inline-flex items-center justify-center gap-2 rounded-2xl font-semibold transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-slate-950 disabled:cursor-not-allowed disabled:opacity-50';
  
  const variantStyles: Record<ButtonVariant, string> = {
    primary: 'border border-sky-400/25 bg-gradient-to-r from-sky-500 to-cyan-400 text-white shadow-[0_18px_38px_rgba(14,165,233,0.22)] hover:translate-y-[-1px] hover:shadow-[0_24px_48px_rgba(14,165,233,0.28)] focus:ring-sky-400/45',
    success: 'border border-emerald-400/20 bg-emerald-500/12 text-emerald-100 hover:bg-emerald-500/18 focus:ring-emerald-400/35',
    error: 'border border-rose-400/20 bg-rose-500/12 text-rose-100 hover:bg-rose-500/18 focus:ring-rose-400/35',
    danger: 'border border-rose-400/20 bg-gradient-to-r from-rose-600 to-red-500 text-white shadow-[0_18px_38px_rgba(244,63,94,0.22)] hover:translate-y-[-1px] hover:shadow-[0_24px_48px_rgba(244,63,94,0.28)] focus:ring-rose-400/35',
    warning: 'border border-amber-400/20 bg-amber-500/12 text-amber-100 hover:bg-amber-500/18 focus:ring-amber-400/35',
    secondary: 'border border-white/10 bg-white/[0.03] text-slate-100 hover:border-white/16 hover:bg-white/[0.06] focus:ring-sky-400/28',
  };
  
  const sizeStyles: Record<ButtonSize, string> = {
    sm: 'min-h-[2.4rem] px-3.5 py-2 text-sm',
    md: 'min-h-[2.9rem] px-4.5 py-2.5 text-sm',
    lg: 'min-h-[3.2rem] px-6 py-3 text-base',
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
