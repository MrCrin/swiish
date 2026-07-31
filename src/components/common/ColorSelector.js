import React from 'react';
import { TAILWIND_COLORS } from '../../constants/colors';

// Color Selector Component
function ColorSelector({ selectedColor, onSelect, label, showAuto = false, autoLabel = "Auto (complementary)" }) {
  const colorGradients = {
    indigo: 'from-indigo-500 to-indigo-700',
    blue: 'from-blue-500 to-blue-700',
    rose: 'from-rose-500 to-rose-700',
    emerald: 'from-emerald-500 to-emerald-700',
    slate: 'from-slate-500 to-slate-700',
    purple: 'from-purple-500 to-purple-700',
    cyan: 'from-cyan-500 to-cyan-700',
    teal: 'from-teal-500 to-teal-700',
    orange: 'from-orange-500 to-orange-700',
    pink: 'from-pink-500 to-pink-700',
    violet: 'from-violet-500 to-violet-700',
    fuchsia: 'from-fuchsia-500 to-fuchsia-700',
    amber: 'from-amber-500 to-amber-700',
    lime: 'from-lime-500 to-lime-700',
    green: 'from-green-500 to-green-700',
    yellow: 'from-yellow-500 to-yellow-700',
    red: 'from-red-500 to-red-700'
  };

  return (
    <div>
      {label && <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">{label}</label>}
      <div className="grid grid-cols-8 gap-2">
        {showAuto && (
          <button
            onClick={() => onSelect(null)}
            className={`w-10 h-10 rounded-full border-thick flex flex-col items-center justify-center text-[10px] font-medium transition-all ${
              selectedColor === null
                ? 'border-indigo-500 dark:border-indigo-400 bg-indigo-50 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300 ring-2 ring-indigo-200 dark:ring-indigo-800'
                : 'border-border dark:border-border-dark bg-surface dark:bg-surface-dark text-text-secondary dark:text-text-secondary-dark hover:border-border-dark dark:hover:border-border-dark'
            }`}
          >
            <span>Auto</span>
          </button>
        )}
        {TAILWIND_COLORS.map(color => (
          <button
            key={color}
            onClick={() => onSelect(color)}
            className={`w-10 h-10 rounded-full border-thick transition-all overflow-hidden ${
              selectedColor === color
                ? 'border-indigo-500 dark:border-indigo-400 ring-2 ring-indigo-200 dark:ring-indigo-800 scale-105'
                : 'border-border dark:border-border-dark hover:border-border-dark dark:hover:border-border-dark'
            }`}
            title={color.charAt(0).toUpperCase() + color.slice(1)}
          >
            <div className={`w-full h-full bg-gradient-to-br ${colorGradients[color] || 'from-gray-500 to-gray-700'}`} />
          </button>
        ))}
      </div>
    </div>
  );
}

export default ColorSelector;
