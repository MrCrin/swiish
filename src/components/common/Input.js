import React from 'react';

function Input({ label, icon: Icon, value, onChange, type = "text", placeholder }) {
  return (
    <div className="space-y-1">
      {label && <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark">{label}</label>}
      <div className="relative">
        {Icon && <Icon className="absolute left-4 top-3 w-5 h-5 text-text-muted-subtle dark:text-text-muted-dark" />}
        <input type={type} value={value || ''} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} className={`w-full ${Icon ? 'pl-11' : 'px-4'} py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark placeholder:text-text-muted-subtle dark:placeholder:text-text-muted-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark`} />
      </div>
    </div>
  );
}

export default Input;
