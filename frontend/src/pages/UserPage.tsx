import React, { useState, FormEvent } from 'react';
import { useAuth } from '../context/AuthContext';
import Button from '../components/Button';
import Card from '../components/Card';

interface UserPageProps {
  onUserCreated?: () => void;
}

const UserPage: React.FC<UserPageProps> = ({ onUserCreated }) => {
  const { currentUser, createUser } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [role, setRole] = useState<'admin' | 'manager' | 'employee'>('employee');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    // Validation
    if (!email || !password || !confirmPassword || !role) {
      setError('Please fill in all fields');
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters long');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError('Please enter a valid email address');
      return;
    }

    try {
      setLoading(true);
      await createUser({ email, password, role });
      setSuccess(`User account created successfully for ${email} with role: ${role}!`);
      // Clear form
      setEmail('');
      setPassword('');
      setConfirmPassword('');
      setRole('employee');
      // Notify parent component if callback provided
      if (onUserCreated) {
        setTimeout(() => {
          onUserCreated();
        }, 1500);
      }
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to create user account';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen">
      <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8 animate-slide-down">
          <div className="flex items-center gap-4 mb-4">
            <div className="w-12 h-12 bg-gradient-to-br from-vt-primary to-vt-success rounded-xl flex items-center justify-center shadow-lg">
              <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
              </svg>
            </div>
            <div>
              <h1 className="text-4xl font-bold gradient-text mb-2">Create New User</h1>
              <p className="text-vt-muted text-lg">Create a new user account (Admin Only)</p>
            </div>
          </div>
        </div>

        {/* Info Card */}
        <Card variant="strong" className="p-6 mb-6 animate-scale-in">
          <div className="flex items-start gap-4">
            <svg className="w-6 h-6 text-vt-primary flex-shrink-0 mt-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <h3 className="text-lg font-bold text-vt-light mb-2">Admin User Creation</h3>
              <p className="text-sm text-vt-muted">
                You are logged in as <span className="text-vt-primary font-medium">{currentUser?.email}</span>. 
                Only authenticated users can create new accounts. The new user will be created in the system and can log in immediately.
              </p>
            </div>
          </div>
        </Card>

        {/* Success Message */}
        {success && (
          <Card variant="strong" className="mb-6 border-vt-success/30 bg-vt-success/10 p-4 animate-slide-up">
            <div className="flex items-center gap-3">
              <svg className="w-5 h-5 text-vt-success flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <p className="text-vt-success font-medium">{success}</p>
            </div>
          </Card>
        )}

        {/* Error Message */}
        {error && (
          <Card variant="strong" className="mb-6 border-vt-error/30 bg-vt-error/10 p-4 animate-slide-up">
            <div className="flex items-center gap-3">
              <svg className="w-5 h-5 text-vt-error flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <p className="text-vt-error font-medium">{error}</p>
            </div>
          </Card>
        )}

        {/* Form Card */}
        <Card variant="strong" className="p-8 animate-slide-up">
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Email Field */}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-vt-light mb-2">
                Email Address
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                  <svg className="w-5 h-5 text-vt-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207" />
                  </svg>
                </div>
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-12 pr-4 py-3 bg-vt-muted/10 border border-vt-muted/20 rounded-lg text-vt-light placeholder-vt-muted focus:outline-none focus:ring-2 focus:ring-vt-primary focus:border-transparent transition-all"
                  placeholder="user@example.com"
                  required
                  disabled={loading}
                />
              </div>
            </div>

            {/* Password Field */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-vt-light mb-2">
                Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                  <svg className="w-5 h-5 text-vt-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                </div>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-12 pr-4 py-3 bg-vt-muted/10 border border-vt-muted/20 rounded-lg text-vt-light placeholder-vt-muted focus:outline-none focus:ring-2 focus:ring-vt-primary focus:border-transparent transition-all"
                  placeholder="Minimum 6 characters"
                  required
                  minLength={6}
                  disabled={loading}
                />
              </div>
              <p className="mt-2 text-xs text-vt-muted">Password must be at least 6 characters long</p>
            </div>

            {/* Confirm Password Field */}
            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-vt-light mb-2">
                Confirm Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                  <svg className="w-5 h-5 text-vt-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <input
                  id="confirmPassword"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full pl-12 pr-4 py-3 bg-vt-muted/10 border border-vt-muted/20 rounded-lg text-vt-light placeholder-vt-muted focus:outline-none focus:ring-2 focus:ring-vt-primary focus:border-transparent transition-all"
                  placeholder="Re-enter password"
                  required
                  minLength={6}
                  disabled={loading}
                />
              </div>
            </div>

            {/* Role Field */}
            <div>
              <label htmlFor="role" className="block text-sm font-medium text-vt-light mb-2">
                Role
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                  <svg className="w-5 h-5 text-vt-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <select
                  id="role"
                  value={role}
                  onChange={(e) => setRole(e.target.value as 'admin' | 'manager' | 'employee')}
                  className="w-full pl-12 pr-4 py-3 bg-vt-muted/10 border border-vt-muted/20 rounded-lg text-vt-light focus:outline-none focus:ring-2 focus:ring-vt-primary focus:border-transparent transition-all appearance-none cursor-pointer"
                  required
                  disabled={loading}
                >
                  <option value="employee">Employee</option>
                  <option value="manager">Manager</option>
                  <option value="admin">Admin</option>
                </select>
                <div className="absolute inset-y-0 right-0 pr-4 flex items-center pointer-events-none">
                  <svg className="w-5 h-5 text-vt-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </div>
              <p className="mt-2 text-xs text-vt-muted">Select the user's role in the system</p>
            </div>

            {/* Submit Button */}
            <Button
              type="submit"
              variant="primary"
              size="lg"
              fullWidth
              isLoading={loading}
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
              </svg>
              <span>Create User Account</span>
            </Button>
          </form>
        </Card>

        {/* Additional Info */}
        <Card variant="default" className="mt-6 p-4 animate-slide-up stagger-1">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-vt-warning flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div className="text-sm text-vt-muted">
              <p className="font-medium text-vt-light mb-1">Important Notes:</p>
              <ul className="list-disc list-inside space-y-1 ml-2">
                <li>The new user can log in immediately after creation</li>
                <li>Make sure to provide the password securely to the new user</li>
                <li>Email addresses must be unique - existing accounts cannot be recreated</li>
              </ul>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
};

export default UserPage;
