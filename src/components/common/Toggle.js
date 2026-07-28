import React from 'react';

function Toggle({ label, description, checked, onChange }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark">{label}</label>
          {description && <p className="text-xs text-text-muted dark:text-text-muted-dark mt-1">{description}</p>}
        </div>
        <button
          type="button"
          onClick={() => onChange(!checked)}
          className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:ring-offset-2 ${
            checked ? 'bg-action dark:bg-action-dark' : 'bg-border dark:bg-surface-dark'
          }`}
        >
          <span
            className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
              checked ? 'translate-x-6' : 'translate-x-1'
            }`}
          />
        </button>
      </div>
    </div>
  );
}

export default Toggle;
