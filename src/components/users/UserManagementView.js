import React, { useState, useEffect } from 'react';
import { Plus, ArrowLeft, User, Edit3, Trash2, Mail, RefreshCw, Check, Save } from 'lucide-react';
import { API_ENDPOINT } from '../../constants/app';

function UserManagementView({ apiCall, userRole, onBack, showAlert, showConfirm }) {
  const [users, setUsers] = useState([]);
  const [invitations, setInvitations] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showCreateUserModal, setShowCreateUserModal] = useState(false);
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [editingUserId, setEditingUserId] = useState(null);
  const [currentUserId, setCurrentUserId] = useState(null);

  const [newUser, setNewUser] = useState({ email: '', password: '', role: 'member' });
  const [newInvitation, setNewInvitation] = useState({ email: '', role: 'member' });
  const [isSaving, setIsSaving] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);

  useEffect(() => {
    fetchCurrentUser();
    fetchUsers();
    fetchInvitations();
  }, []);

  const fetchCurrentUser = async () => {
    try {
      const res = await apiCall(`${API_ENDPOINT}/auth/me`);
      if (res.ok) {
        const userData = await res.json();
        setCurrentUserId(userData.id);
      }
    } catch (e) {
      console.error('Failed to fetch current user:', e);
    }
  };

  const fetchUsers = async () => {
    try {
      const res = await apiCall(`${API_ENDPOINT}/admin/users`);
      if (res.ok) {
        const data = await res.json();
        setUsers(data);
      } else {
        if (showAlert) showAlert('Failed to load users', 'error');
      }
    } catch (e) {
      console.error('Failed to fetch users:', e);
      if (showAlert) showAlert('Error loading users', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const fetchInvitations = async () => {
    try {
      const res = await apiCall(`${API_ENDPOINT}/admin/invitations`);
      if (res.ok) {
        const data = await res.json();
        setInvitations(data.invitations);
      }
    } catch (e) {
      console.error('Failed to fetch invitations:', e);
    }
  };

  const handleCreateUser = async () => {
    if (!newUser.email || !newUser.password) {
      if (showAlert) showAlert('Email and password are required', 'error');
      return;
    }

    if (newUser.password.length < 8) {
      if (showAlert) showAlert('Password must be at least 8 characters long', 'error');
      return;
    }

    setIsSaving(true);
    try {
      const res = await apiCall(`${API_ENDPOINT}/admin/users`, {
        method: 'POST',
        body: JSON.stringify(newUser)
      });

      if (res.ok) {
        setIsSuccess(true);
        setTimeout(() => setIsSuccess(false), 2000);
        setShowCreateUserModal(false);
        setNewUser({ email: '', password: '', role: 'member' });
        fetchUsers();
      } else {
        // Try to parse error response
        let errorMessage = 'Failed to create user';
        try {
          const errorData = await res.json();
          errorMessage = errorData.error || errorData.message || errorMessage;
          console.error('User creation failed:', {
            status: res.status,
            statusText: res.statusText,
            error: errorData
          });
        } catch (parseError) {
          // Response is not JSON, use status text
          console.error('User creation failed - non-JSON response:', {
            status: res.status,
            statusText: res.statusText
          });
          errorMessage = `Failed to create user: ${res.status} ${res.statusText}`;
        }
        if (showAlert) showAlert(errorMessage, 'error');
      }
    } catch (e) {
      console.error('Error creating user:', e);
      const errorMessage = e.message || 'Error creating user. Please try again.';
      if (showAlert) showAlert(errorMessage, 'error');
    } finally {
      setIsSaving(false);
    }
  };

  const handleSendInvitation = async () => {
    if (!newInvitation.email) {
      if (showAlert) showAlert('Email is required', 'error');
      return;
    }

    setIsSaving(true);
    try {
      const res = await apiCall(`${API_ENDPOINT}/admin/invitations`, {
        method: 'POST',
        body: JSON.stringify(newInvitation)
      });
      if (res.ok) {
        const data = await res.json();
        setIsSuccess(true);
        setTimeout(() => setIsSuccess(false), 2000);
        setShowInviteModal(false);
        setNewInvitation({ email: '', role: 'member' });

        // Show warning if email failed
        if (data.status === 'failed' && showAlert) {
          showAlert('Invitation created but email failed to send. You can retry from the invitations list below.', 'warning');
        }

        // Reload invitations list
        fetchInvitations();
      } else {
        const errorData = await res.json().catch(() => ({}));
        if (showAlert) showAlert(errorData.error || 'Failed to send invitation', 'error');
      }
    } catch (e) {
      if (showAlert) showAlert('Error sending invitation', 'error');
    } finally {
      setIsSaving(false);
    }
  };

  const handleUpdateRole = async (userId, newRole) => {
    try {
      const res = await apiCall(`${API_ENDPOINT}/admin/users/${userId}`, {
        method: 'PATCH',
        body: JSON.stringify({ role: newRole })
      });
      if (res.ok) {
        if (showAlert) showAlert('User role updated successfully', 'success');
        fetchUsers();
        setEditingUserId(null);
      } else {
        const errorData = await res.json().catch(() => ({}));
        if (showAlert) showAlert(errorData.error || 'Failed to update role', 'error');
      }
    } catch (e) {
      if (showAlert) showAlert('Error updating role', 'error');
    }
  };

  const handleRemoveUser = async (userId, userEmail) => {
    if (showConfirm) {
      showConfirm(
        `Are you sure you want to permanently delete ${userEmail}? This will delete the user and all their cards. This action cannot be undone.`,
        async () => {
          try {
            const res = await apiCall(`${API_ENDPOINT}/admin/users/${userId}`, {
              method: 'DELETE'
            });
            if (res.ok) {
              if (showAlert) showAlert('User deleted successfully', 'success');
              fetchUsers();
            } else {
              const errorData = await res.json().catch(() => ({}));
              if (showAlert) showAlert(errorData.error || 'Failed to delete user', 'error');
            }
          } catch (e) {
            if (showAlert) showAlert('Error deleting user', 'error');
          }
        },
        'Delete User',
        'Delete',
        'Cancel'
      );
    }
  };

  const handleRetryInvitation = async (invitationId) => {
    try {
      const res = await apiCall(`${API_ENDPOINT}/admin/invitations/${invitationId}/retry`, {
        method: 'POST'
      });
      if (res.ok) {
        const data = await res.json();
        if (showAlert) {
          showAlert(data.success ? 'Invitation email sent successfully' : 'Failed to send invitation email',
                    data.success ? 'success' : 'error');
        }
        fetchInvitations();
      }
    } catch (e) {
      if (showAlert) showAlert('Error retrying invitation', 'error');
    }
  };

  const handleDeleteInvitation = async (invitationId) => {
    if (showConfirm) {
      showConfirm(
        'Are you sure you want to delete this invitation?',
        async () => {
          try {
            const res = await apiCall(`${API_ENDPOINT}/admin/invitations/${invitationId}`, {
              method: 'DELETE'
            });
            if (res.ok) {
              if (showAlert) showAlert('Invitation deleted', 'success');
              fetchInvitations();
            }
          } catch (e) {
            if (showAlert) showAlert('Error deleting invitation', 'error');
          }
        },
        'Delete Invitation',
        'Delete',
        'Cancel'
      );
    }
  };

  if (userRole !== 'owner') {
    return (
      <div className="min-h-screen bg-main dark:bg-main-dark flex items-center justify-center p-6">
        <div className="bg-card dark:bg-card-dark rounded-card p-8 shadow-lg max-w-md w-full">
          <h2 className="text-xl font-bold text-text-primary dark:text-text-primary-dark mb-4">Access Denied</h2>
          <p className="text-text-secondary dark:text-text-muted-dark mb-6">You don't have permission to manage users.</p>
          <button onClick={onBack} className="px-4 py-2 bg-confirm dark:bg-confirm-dark text-confirm-text dark:text-confirm-text-dark rounded-full text-sm font-bold">
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-main dark:bg-main-dark bg-main-texture flex flex-col">
      <div className="w-full bg-card dark:bg-card-dark border-b border-border dark:border-border-dark">
        <div className="p-6 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button onClick={onBack} className="p-2 hover:bg-surface dark:hover:bg-surface-dark rounded-full text-text-muted dark:text-text-muted-dark">
              <ArrowLeft className="w-5 h-5"/>
            </button>
            <div>
              <h1 className="text-xl font-bold text-text-primary dark:text-text-primary-dark">User Management</h1>
              <p className="text-sm text-text-secondary dark:text-text-muted-dark">Manage users and invitations for your organisation</p>
            </div>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => setShowInviteModal(true)}
              className="px-4 py-2 bg-action dark:bg-action-dark text-white rounded-full text-sm font-bold flex items-center gap-2 hover:bg-action-hover dark:hover:bg-action-hover-dark"
            >
              <Plus className="w-4 h-4" /> Invite User
            </button>
            <button
              onClick={() => setShowCreateUserModal(true)}
              className="px-4 py-2 bg-confirm dark:bg-confirm-dark text-confirm-text dark:text-confirm-text-dark rounded-full text-sm font-bold flex items-center gap-2 hover:bg-confirm-hover dark:hover:bg-confirm-hover-dark"
            >
              <Plus className="w-4 h-4" /> Create User
            </button>
          </div>
        </div>
      </div>

      <div className="flex-1 p-6 max-w-6xl mx-auto w-full">
        {isLoading ? (
          <div className="text-center py-12">
            <div className="text-text-secondary dark:text-text-muted-dark">Loading users...</div>
          </div>
        ) : (
          <div className="space-y-6">
            <div className="bg-card dark:bg-card-dark rounded-input shadow-sm border border-border dark:border-border-dark overflow-hidden">
              <div className="p-6 border-b border-border dark:border-border-dark">
                <h2 className="text-lg font-semibold text-text-primary dark:text-text-primary-dark">Organisation Users</h2>
                <p className="text-sm text-text-secondary dark:text-text-muted-dark mt-1">Users currently in your organisation</p>
              </div>
              <div className="divide-y divide-slate-200 dark:divide-slate-700">
                {users.length === 0 ? (
                  <div className="p-6 text-center text-text-muted dark:text-text-muted-dark">
                    No users found
                  </div>
                ) : (
                  users.map((user) => {
                    const isCurrentUser = user.id === currentUserId;
                    return (
                      <div key={user.id} className="p-6 flex items-center justify-between hover:bg-surface dark:hover:bg-surface-dark/50 transition-colors">
                        <div className="flex-1">
                          <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-full bg-indigo-100 dark:bg-indigo-900/30 flex items-center justify-center">
                              <User className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                            </div>
                            <div>
                              <div className="font-medium text-text-primary dark:text-text-primary-dark flex items-center gap-2">
                                {user.email}
                                {isCurrentUser && (
                                  <span className="text-xs text-text-muted dark:text-text-muted-dark">(You)</span>
                                )}
                              </div>
                              <div className="text-sm text-text-muted dark:text-text-muted-dark">
                                {user.role === 'owner' ? (
                                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-badge text-xs font-medium bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300">
                                    Owner
                                  </span>
                                ) : (
                                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-badge text-xs font-medium bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark">
                                    Member
                                  </span>
                                )}
                                <span className="ml-2">Joined {new Date(user.created_at).toLocaleDateString()}</span>
                              </div>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          {isCurrentUser ? (
                            <span className="text-xs text-text-muted dark:text-text-muted-dark italic">Cannot modify yourself</span>
                          ) : editingUserId === user.id ? (
                            <div className="flex items-center gap-2">
                              <select
                                value={user.role}
                                onChange={(e) => handleUpdateRole(user.id, e.target.value)}
                                className="px-3 py-1.5 text-sm rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark"
                              >
                                <option value="member">Member</option>
                                <option value="owner">Owner</option>
                              </select>
                              <button
                                onClick={() => setEditingUserId(null)}
                                className="px-3 py-1.5 text-sm bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark rounded-button hover:bg-surface dark:hover:bg-surface-dark"
                              >
                                Cancel
                              </button>
                            </div>
                          ) : (
                            <>
                              <button
                                onClick={() => setEditingUserId(user.id)}
                                className="px-3 py-1.5 text-sm bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark rounded-button hover:bg-surface dark:hover:bg-surface-dark flex items-center gap-1"
                              >
                                <Edit3 className="w-3 h-3" /> Change Role
                              </button>
                              <button
                                onClick={() => handleRemoveUser(user.id, user.email)}
                                className="px-3 py-1.5 text-sm bg-error-bg dark:bg-error-bg-dark text-error dark:text-error-text-dark rounded-badge hover:bg-error-bg dark:hover:bg-error-bg-dark flex items-center gap-1"
                              >
                                <Trash2 className="w-3 h-3" /> Remove
                              </button>
                            </>
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Pending Invitations Section */}
            <div className="bg-card dark:bg-card-dark rounded-input shadow-sm border border-border dark:border-border-dark overflow-hidden">
              <div className="p-6 border-b border-border dark:border-border-dark">
                <h2 className="text-lg font-semibold text-text-primary dark:text-text-primary-dark">Pending Invitations</h2>
                <p className="text-sm text-text-secondary dark:text-text-muted-dark mt-1">Invitations sent but not yet accepted</p>
              </div>
              <div className="divide-y divide-slate-200 dark:divide-slate-700">
                {invitations.filter(inv => inv.status !== 'accepted' && !inv.accepted_at).length === 0 ? (
                  <div className="p-6 text-center text-text-muted dark:text-text-muted-dark">
                    No pending invitations
                  </div>
                ) : (
                  invitations.filter(inv => inv.status !== 'accepted' && !inv.accepted_at).map(inv => (
                    <div key={inv.id} className="p-6 flex items-center justify-between hover:bg-surface dark:hover:bg-surface-dark/50 transition-colors">
                      <div className="flex-1">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-full bg-amber-100 dark:bg-amber-900/30 flex items-center justify-center">
                            <Mail className="w-5 h-5 text-amber-600 dark:text-amber-400" />
                          </div>
                          <div>
                            <div className="font-medium text-text-primary dark:text-text-primary-dark">
                              {inv.email}
                            </div>
                            <div className="text-sm text-text-muted dark:text-text-muted-dark flex items-center gap-2 mt-1">
                              <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-badge text-xs font-medium ${
                                inv.status === 'sent' ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300' :
                                inv.status === 'failed' ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300' :
                                inv.status === 'pending' ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300' :
                                inv.status === 'expired' ? 'bg-gray-100 dark:bg-gray-900/30 text-gray-700 dark:text-gray-300' :
                                'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300'
                              }`}>
                                {inv.status === 'sent' && 'Sent'}
                                {inv.status === 'failed' && 'Failed'}
                                {inv.status === 'pending' && 'Pending'}
                                {inv.status === 'expired' && 'Expired'}
                              </span>
                              {inv.role === 'owner' ? (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-badge text-xs font-medium bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300">
                                  Owner
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-badge text-xs font-medium bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark">
                                  Member
                                </span>
                              )}
                              {inv.invited_by_email && (
                                <span className="text-xs">invited by {inv.invited_by_email}</span>
                              )}
                              <span className="text-xs">• {new Date(inv.created_at).toLocaleDateString()}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        {(inv.status === 'failed' || inv.status === 'pending') && (
                          <button
                            onClick={() => handleRetryInvitation(inv.id)}
                            className="px-3 py-1.5 text-sm bg-action dark:bg-action-dark text-white rounded-button hover:bg-action-hover dark:hover:bg-action-hover-dark flex items-center gap-1"
                            title="Retry sending email"
                          >
                            <RefreshCw className="w-3 h-3" /> Retry
                          </button>
                        )}
                        <button
                          onClick={() => handleDeleteInvitation(inv.id)}
                          className="px-3 py-1.5 text-sm bg-error-bg dark:bg-error-bg-dark text-error dark:text-error-text-dark rounded-badge hover:bg-error-bg dark:hover:bg-error-bg-dark flex items-center gap-1"
                          title="Delete invitation"
                        >
                          <Trash2 className="w-3 h-3" /> Delete
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Create User Modal */}
      {showCreateUserModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
          <div className="bg-card dark:bg-card-dark rounded-card shadow-xl max-w-md w-full p-6">
            <h3 className="text-lg font-bold text-text-primary dark:text-text-primary-dark mb-4">Create New User</h3>
            <div className="space-y-4">
              <div>
                <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Email</label>
                <input
                  type="email"
                  value={newUser.email}
                  onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                  className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                  placeholder="user@example.com"
                />
              </div>
              <div>
                <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Password</label>
                <input
                  type="password"
                  value={newUser.password}
                  onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                  className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                  placeholder="Minimum 8 characters"
                />
              </div>
              <div>
                <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Role</label>
                <select
                  value={newUser.role}
                  onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                  className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                >
                  <option value="member">Member</option>
                  <option value="owner">Owner</option>
                </select>
              </div>
            </div>
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => {
                  setShowCreateUserModal(false);
                  setNewUser({ email: '', password: '', role: 'member' });
                }}
                className="flex-1 px-4 py-2.5 bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark rounded-button font-medium hover:bg-surface dark:hover:bg-surface-dark"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateUser}
                disabled={isSaving}
                className="flex-1 px-4 py-2.5 bg-confirm dark:bg-confirm-dark text-confirm-text dark:text-confirm-text-dark rounded-button font-bold hover:bg-confirm-hover dark:hover:bg-confirm-hover-dark disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {isSaving ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : isSuccess ? (
                  <Check className="w-4 h-4 text-green-500" />
                ) : (
                  <Save className="w-4 h-4" />
                )}
                {isSaving ? 'Creating...' : 'Create User'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Invite User Modal */}
      {showInviteModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
          <div className="bg-card dark:bg-card-dark rounded-card shadow-xl max-w-md w-full p-6">
            <h3 className="text-lg font-bold text-text-primary dark:text-text-primary-dark mb-4">Invite User</h3>
            <div className="space-y-4">
              <div>
                <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Email</label>
                <input
                  type="email"
                  value={newInvitation.email}
                  onChange={(e) => setNewInvitation({ ...newInvitation, email: e.target.value })}
                  className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                  placeholder="user@example.com"
                />
                <p className="text-xs text-text-muted dark:text-text-muted-dark mt-1">An invitation email will be sent to this address</p>
              </div>
              <div>
                <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Role</label>
                <select
                  value={newInvitation.role}
                  onChange={(e) => setNewInvitation({ ...newInvitation, role: e.target.value })}
                  className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                >
                  <option value="member">Member</option>
                  <option value="owner">Owner</option>
                </select>
              </div>
            </div>
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => {
                  setShowInviteModal(false);
                  setNewInvitation({ email: '', role: 'member' });
                }}
                className="flex-1 px-4 py-2.5 bg-surface dark:bg-surface-dark text-text-primary dark:text-text-secondary-dark rounded-button font-medium hover:bg-surface dark:hover:bg-surface-dark"
              >
                Cancel
              </button>
              <button
                onClick={handleSendInvitation}
                disabled={isSaving || isSuccess}
                className={`flex-1 px-4 py-2.5 rounded-button font-bold flex items-center justify-center gap-2 transition-all ${
                  isSuccess
                    ? 'bg-green-500 dark:bg-green-600 text-white hover:bg-green-600 dark:hover:bg-green-700'
                    : 'bg-action dark:bg-action-dark text-white hover:bg-action-hover dark:hover:bg-action-hover-dark disabled:opacity-50'
                }`}
              >
                {isSaving ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Sending...
                  </>
                ) : isSuccess ? (
                  <>
                    <Check className="w-4 h-4" />
                    Sent!
                  </>
                ) : (
                  <>
                    <Save className="w-4 h-4" />
                    Send Invitation
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default UserManagementView;
