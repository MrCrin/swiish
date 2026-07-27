import React from 'react';
import { AlertCircle, Check } from 'lucide-react';

// Modal Component
function Modal({ isOpen, onClose, type = 'info', title, message, onConfirm, confirmText = 'OK', cancelText = 'Cancel', inputLabel, inputPlaceholder, inputValue, onInputChange }) {
  if (!isOpen) return null;

  const typeStyles = {
    info: { icon: AlertCircle, iconColor: 'text-info-text dark:text-info-text-dark', bgColor: 'bg-info-bg dark:bg-info-bg-dark', borderColor: 'border-info-border dark:border-info-border-dark' },
    success: { icon: Check, iconColor: 'text-success-text dark:text-success-text-dark', bgColor: 'bg-success-bg dark:bg-success-bg-dark', borderColor: 'border-success-border dark:border-success-border-dark' },
    error: { icon: AlertCircle, iconColor: 'text-error-text dark:text-error-text-dark', bgColor: 'bg-error-bg dark:bg-error-bg-dark', borderColor: 'border-error-border dark:border-error-border-dark' },
    confirm: { icon: AlertCircle, iconColor: 'text-text-muted dark:text-text-muted-dark', bgColor: 'bg-surface dark:bg-surface-dark', borderColor: 'border-border dark:border-border-dark' }
  };

  const style = typeStyles[type] || typeStyles.info;
  const Icon = style.icon;
  const hasInput = inputLabel || inputPlaceholder;

  const handleConfirm = () => {
    if (onConfirm) {
      onConfirm();
    }
    // onClose will handle calling the onClose callback
    onClose();
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && hasInput) {
      handleConfirm();
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 dark:bg-black/80 backdrop-blur-sm z-[100] flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="bg-card dark:bg-card-dark rounded-card shadow-2xl max-w-sm w-full p-6 animate-in fade-in duration-200"
        onClick={(e) => e.stopPropagation()}
      >
        <div className={`w-12 h-12 rounded-full ${style.bgColor} flex items-center justify-center mx-auto mb-4`}>
          <Icon className={`w-6 h-6 ${style.iconColor}`} />
        </div>
        {title && <h3 className="text-xl font-bold text-text-primary dark:text-text-primary-dark text-center mb-2">{title}</h3>}
        {message && <p className="text-text-secondary dark:text-text-secondary-dark text-center mb-6">{message}</p>}
        {hasInput && (
          <div className="mb-6">
            {inputLabel && <label className="block text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2">{inputLabel}</label>}
            <input
              type="text"
              value={inputValue || ''}
              onChange={(e) => onInputChange && onInputChange(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder={inputPlaceholder}
              className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
              autoFocus
            />
          </div>
        )}
        <div className="flex gap-3">
          {(type === 'confirm' || hasInput) && (
            <button
              onClick={onClose}
              className="flex-1 px-4 py-2.5 rounded-full font-medium text-text-secondary dark:text-text-secondary-dark bg-surface dark:bg-surface-dark hover:bg-surface dark:hover:bg-surface-dark transition-colors"
            >
              {cancelText}
            </button>
          )}
          <button
            onClick={handleConfirm}
            className={`flex-1 px-4 py-2.5 rounded-full font-bold text-white transition-colors ${
              type === 'error' ? 'bg-error dark:bg-error-dark hover:bg-error-hover dark:hover:bg-error-hover-dark' :
              type === 'success' ? 'bg-success dark:bg-success-dark hover:bg-success-hover dark:hover:bg-success-hover-dark' :
              type === 'confirm' ? 'bg-confirm dark:bg-confirm-dark hover:bg-confirm-hover dark:hover:bg-confirm-hover-dark text-confirm-text dark:text-confirm-text-dark' :
              'bg-info dark:bg-info-dark hover:bg-info-hover dark:hover:bg-info-hover-dark'
            }`}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}

export default Modal;
