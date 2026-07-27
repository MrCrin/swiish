import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { RefreshCw, AlertCircle, Check } from 'lucide-react';

function InvitationAcceptance({ apiCall, showAlert, API_ENDPOINT }) {
  const { token } = useParams();
  const navigate = useNavigate();
  const [invitation, setInvitation] = useState(null);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [passwordError, setPasswordError] = useState(null);
  const [hasAccepted, setHasAccepted] = useState(false);

  // Fetch invitation details on mount
  useEffect(() => {
    // Don't fetch if invitation has already been accepted
    if (hasAccepted) return;

    const fetchInvitation = async () => {
      try {
        const res = await apiCall(`${API_ENDPOINT}/invitations/${token}`, { method: 'GET' });
        if (res.ok) {
          const data = await res.json();
          setInvitation(data);
          setError(null);
        } else {
          const errorData = await res.json().catch(() => ({}));
          // If already accepted, treat as success and redirect
          if (errorData.error && errorData.error.includes('already been accepted')) {
            if (showAlert) showAlert('Welcome! Your account has been created.', 'success');
            setTimeout(() => navigate('/'), 500);
          } else {
            setError(errorData.error || 'Invitation not found or has expired');
            setInvitation(null);
          }
        }
      } catch (e) {
        setError('Error loading invitation');
        setInvitation(null);
      } finally {
        setIsLoading(false);
      }
    };

    if (token) {
      fetchInvitation();
    }
  }, [token, apiCall, API_ENDPOINT, hasAccepted, showAlert, navigate]);

  const validatePasswords = () => {
    setPasswordError(null);

    if (!password) {
      setPasswordError('Password is required');
      return false;
    }

    if (password.length < 8) {
      setPasswordError('Password must be at least 8 characters');
      return false;
    }

    if (password !== confirmPassword) {
      setPasswordError('Passwords do not match');
      return false;
    }

    return true;
  };

  const handleAcceptInvitation = async (e) => {
    e.preventDefault();

    if (!validatePasswords()) {
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await apiCall(`${API_ENDPOINT}/invitations/${token}/accept`, {
        method: 'POST',
        body: JSON.stringify({ password })
      });

      if (res.ok) {
        const data = await res.json();
        // Set flag immediately to prevent re-fetching during redirect window
        setHasAccepted(true);
        if (showAlert) showAlert('Welcome! Your account has been created.', 'success');
        // Redirect to dashboard
        setTimeout(() => navigate('/'), 1000);
      } else {
        const errorData = await res.json().catch(() => ({}));
        setPasswordError(errorData.error || 'Failed to accept invitation');
      }
    } catch (e) {
      setPasswordError('Error accepting invitation');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-bg dark:bg-bg-dark">
        <div className="text-center">
          <RefreshCw className="w-8 h-8 animate-spin text-action dark:text-action-dark mx-auto mb-4" />
          <p className="text-text-primary dark:text-text-primary-dark">Loading invitation...</p>
        </div>
      </div>
    );
  }

  if (error || !invitation) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-bg dark:bg-bg-dark p-4">
        <div className="max-w-md w-full bg-card dark:bg-card-dark rounded-card shadow-lg p-8 text-center">
          <AlertCircle className="w-12 h-12 text-red-500 mx-auto mb-4" />
          <h1 className="text-xl font-bold text-text-primary dark:text-text-primary-dark mb-2">Invitation Invalid</h1>
          <p className="text-text-secondary dark:text-text-secondary-dark mb-6">{error || 'This invitation link is not valid or has expired.'}</p>
          <button
            onClick={() => navigate('/')}
            className="w-full px-4 py-2.5 bg-action dark:bg-action-dark text-white rounded-button font-medium hover:bg-action-hover dark:hover:bg-action-hover-dark"
          >
            Go to Login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-bg dark:bg-bg-dark p-4">
      <div className="max-w-md w-full">
        <div className="bg-card dark:bg-card-dark rounded-card shadow-lg p-8 mb-4">
          <h1 className="text-2xl font-bold text-text-primary dark:text-text-primary-dark mb-2">Join {invitation.organisationName}</h1>
          <p className="text-text-secondary dark:text-text-secondary-dark mb-6">
            You've been invited to join as a <span className="font-semibold capitalize">{invitation.role}</span>
          </p>

          <form onSubmit={handleAcceptInvitation} className="space-y-4">
            {/* Email display */}
            <div>
              <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark block mb-2">Email</label>
              <input
                type="email"
                value={invitation.email}
                disabled
                className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-surface dark:bg-surface-dark text-text-secondary dark:text-text-secondary-dark"
              />
            </div>

            {/* Password input */}
            <div>
              <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark block mb-2">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setPasswordError(null);
                }}
                placeholder="Enter password (min 8 characters)"
                className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
              />
            </div>

            {/* Confirm password input */}
            <div>
              <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark block mb-2">Confirm Password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => {
                  setConfirmPassword(e.target.value);
                  setPasswordError(null);
                }}
                placeholder="Confirm password"
                className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
              />
            </div>

            {/* Error message */}
            {passwordError && (
              <div className="p-3 bg-red-100 dark:bg-red-900/30 border border-red-300 dark:border-red-700 rounded-input text-red-700 dark:text-red-200 text-sm">
                {passwordError}
              </div>
            )}

            {/* Submit button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full px-4 py-2.5 bg-action dark:bg-action-dark text-white rounded-button font-bold hover:bg-action-hover dark:hover:bg-action-hover-dark disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {isSubmitting ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Creating Account...
                </>
              ) : (
                <>
                  <Check className="w-4 h-4" />
                  Accept Invitation
                </>
              )}
            </button>
          </form>

          <p className="text-xs text-text-muted dark:text-text-muted-dark text-center mt-4">
            By accepting this invitation, you agree to join the organization
          </p>
        </div>
      </div>
    </div>
  );
}

export default InvitationAcceptance;
