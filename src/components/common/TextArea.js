import React from 'react';

function TextArea({ label, value, onChange }) {
  return (
    <div className="space-y-1">
      <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark">{label}</label>
      <textarea value={value || ''} onChange={(e) => onChange(e.target.value)} rows={3} className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark resize-none" />
    </div>
  );
}

export default TextArea;
