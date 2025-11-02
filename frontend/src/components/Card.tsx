import React from 'react';

export type CardVariant = 'default' | 'strong' | 'elevated';

export interface CardProps {
  variant?: CardVariant;
  className?: string;
  children: React.ReactNode;
  onClick?: () => void;
}

const Card: React.FC<CardProps> = ({
  variant = 'default',
  className = '',
  children,
  onClick,
}) => {
  const baseStyles = 'rounded-2xl transition-all duration-300';
  
  const variantStyles: Record<CardVariant, string> = {
    default: 'glass border border-vt-primary/20',
    strong: 'glass-strong border border-vt-primary/20 shadow-2xl',
    elevated: 'glass-strong border border-vt-primary/30 shadow-2xl hover:shadow-3xl hover:-translate-y-1',
  };
  
  const clickableStyle = onClick ? 'cursor-pointer hover:border-vt-primary/40' : '';
  
  return (
    <div
      className={`${baseStyles} ${variantStyles[variant]} ${clickableStyle} ${className}`}
      onClick={onClick}
      onKeyDown={(e) => {
        if (onClick && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault();
          onClick();
        }
      }}
      tabIndex={onClick ? 0 : undefined}
    >
      {children}
    </div>
  );
};

export default Card;

