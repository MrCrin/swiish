import React from 'react';
import { Lock } from 'lucide-react';

function LockedOption({ message, children }) {
  return (
    <div className="relative">
      <div className="opacity-50 pointer-events-none">
        {children}
      </div>
      <div className="absolute inset-0 flex items-center justify-center bg-surface/80 dark:bg-card-dark/80 rounded-container border-thick border-dashed border-border dark:border-border-dark">
        <div className="bg-input-bg dark:bg-input-bg-dark rounded-container p-4 border border-border dark:border-border-dark shadow-lg max-w-sm mx-4">
          <div className="flex items-center gap-3 mb-2">
            <Lock className="w-5 h-5 text-text-muted dark:text-text-muted-dark" />
            <span className="text-sm font-semibold text-text-primary dark:text-text-secondary-dark">Locked by Organisation</span>
          </div>
          <p className="text-xs text-text-secondary dark:text-text-muted-dark">{message}</p>
        </div>
      </div>
    </div>
  );
}

export default LockedOption;
