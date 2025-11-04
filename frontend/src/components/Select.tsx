import React from 'react';

export interface SelectOption<T extends string | number = string> {
  label: string;
  value: T;
}

export interface SelectProps<T extends string | number = string> extends Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'onChange' | 'value' | 'size'> {
  id?: string;
  name?: string;
  value: T | '';
  onChange: (value: T | '') => void;
  options: SelectOption<T>[];
  placeholder?: string;
  className?: string;
  density?: 'sm' | 'md';
}

const Select = <T extends string | number = string>({
  id,
  name,
  value,
  onChange,
  options,
  placeholder,
  disabled,
  className = '',
  density = 'md',
  ...rest
}: SelectProps<T>) => {
  const sizeClasses = density === 'sm' ? 'px-3 py-2' : 'px-4 py-3';
  return (
    <div className="relative">
      <select
        id={id}
        name={name}
        value={value as string | number}
        onChange={(e) => onChange((e.target.value as unknown) as T)}
        disabled={disabled}
        className={`w-full ${sizeClasses} bg-vt-dark/50 border border-vt-muted/30 rounded-lg text-vt-light focus:outline-none focus:ring-2 focus:ring-vt-primary focus:border-transparent transition-all appearance-none cursor-pointer ${className}`}
        style={{ colorScheme: 'dark' }}
        {...rest}
      >
        {placeholder !== undefined && (
          <option value="" style={{ backgroundColor: '#1a1a1a', color: '#9ca3af' }}>
            {placeholder}
          </option>
        )}
        {options.map((opt) => (
          <option
            key={String(opt.value)}
            value={opt.value as string | number}
            style={{ backgroundColor: '#1a1a1a', color: '#e5e5e5' }}
          >
            {opt.label}
          </option>
        ))}
      </select>
      <div className="absolute inset-y-0 right-0 pr-4 flex items-center pointer-events-none">
        <svg className="w-5 h-5 text-vt-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </div>
    </div>
  );
};

export default Select;


