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
  const sizeClasses = density === 'sm' ? 'min-h-[2.6rem] px-3.5 py-2 text-sm' : 'min-h-[3rem] px-4 py-3 text-sm';
  return (
    <div className="relative">
      <select
        id={id}
        name={name}
        value={value}
        onChange={(e) => onChange(e.target.value as T | '')}
        disabled={disabled}
        className={`w-full appearance-none rounded-2xl border border-white/10 bg-slate-950/75 ${sizeClasses} text-slate-100 outline-none transition focus:border-sky-400/30 focus:ring-2 focus:ring-sky-400/20 disabled:cursor-not-allowed disabled:opacity-60 ${className}`}
        style={{ colorScheme: 'dark' }}
        {...rest}
      >
        {placeholder !== undefined && (
          <option value="" style={{ backgroundColor: '#0f172a', color: '#94a3b8' }}>
            {placeholder}
          </option>
        )}
        {options.map((opt) => (
          <option
            key={String(opt.value)}
            value={opt.value}
            style={{ backgroundColor: '#0f172a', color: '#e2e8f0' }}
          >
            {opt.label}
          </option>
        ))}
      </select>
      <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-4">
        <svg className="h-5 w-5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </div>
    </div>
  );
};

export default Select;
