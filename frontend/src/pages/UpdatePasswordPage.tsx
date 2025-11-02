import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { userService, PasswordUpdate } from '../services/userService';
import Button from '../components/Button';
import Card from '../components/Card';

const UpdatePasswordPage: React.FC = () => {
  const { currentUser } = useAuth();
  const navigate = useNavigate();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(false);

    // Validation
    if (!currentPassword || !newPassword || !confirmPassword) {
      setError('All fields are required');
      return;
    }

    if (newPassword.length < 6) {
      setError('New password must be at least 6 characters long');
      return;
    }

    if (newPassword !== confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    if (currentPassword === newPassword) {
      setError('New password must be different from current password');
      return;
    }

    if (!currentUser?.uid) {
      setError('User ID not found');
      return;
    }

    try {
      setLoading(true);
      const passwordData: PasswordUpdate = {
        new_password: newPassword,
        current_password: currentPassword,
      };
      
      await userService.updateUserPassword(currentUser.uid, passwordData);
      setSuccess(true);
      
      // Clear form
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      
      // Redirect after 2 seconds
      setTimeout(() => {
        navigate('/profile');
      }, 2000);
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to update password';
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
          <Button
            variant="secondary"
            onClick={() => navigate('/profile')}
            className="mb-4"
            size="sm"
          >
            <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
            Back to Profile
          </Button>
          <h1 className="text-4xl font-bold gradient-text mb-2">Update Password</h1>
          <p className="text-vt-muted text-lg">Change your account password</p>
        </div>

        {/* Success Message */}
        {success && (
          <Card variant="strong" className="mb-6 border-vt-success/30 bg-vt-success/10 p-4 animate-slide-up">
            <div className="flex items-center gap-3">
              <svg className="w-5 h-5 text-vt-success flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <p className="text-vt-success font-medium">Password updated successfully! Redirecting to profile...</p>
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

        {/* Password Update Form */}
        <Card variant="strong" className="p-8 animate-slide-up">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="currentPassword" className="block text-sm font-medium text-vt-light mb-2">
                Current Password
              </label>
              <input
                type="password"
                id="currentPassword"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className="w-full px-4 py-3 bg-vt-dark/50 border border-vt-muted/30 rounded-lg text-vt-light placeholder-vt-muted focus:outline-none focus:ring-2 focus:ring-vt-primary focus:border-transparent transition-all"
                placeholder="Enter current password"
                required
                autoComplete="current-password"
              />
            </div>

            <div>
              <label htmlFor="newPassword" className="block text-sm font-medium text-vt-light mb-2">
                New Password
              </label>
              <input
                type="password"
                id="newPassword"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full px-4 py-3 bg-vt-dark/50 border border-vt-muted/30 rounded-lg text-vt-light placeholder-vt-muted focus:outline-none focus:ring-2 focus:ring-vt-primary focus:border-transparent transition-all"
                placeholder="Enter new password (min. 6 characters)"
                required
                minLength={6}
                autoComplete="new-password"
              />
              <p className="mt-2 text-xs text-vt-muted">Password must be at least 6 characters long</p>
            </div>

            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-vt-light mb-2">
                Confirm New Password
              </label>
              <input
                type="password"
                id="confirmPassword"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full px-4 py-3 bg-vt-dark/50 border border-vt-muted/30 rounded-lg text-vt-light placeholder-vt-muted focus:outline-none focus:ring-2 focus:ring-vt-primary focus:border-transparent transition-all"
                placeholder="Confirm new password"
                required
                minLength={6}
                autoComplete="new-password"
              />
            </div>

            <div className="flex gap-4 pt-4">
              <Button
                type="button"
                variant="secondary"
                onClick={() => navigate('/profile')}
                className="flex-1"
              >
                Cancel
              </Button>
              <Button
                type="submit"
                variant="primary"
                isLoading={loading}
                className="flex-1"
              >
                Update Password
              </Button>
            </div>
          </form>
        </Card>
      </div>
    </div>
  );
};

export default UpdatePasswordPage;

