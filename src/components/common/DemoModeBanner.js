import React from 'react';

// Demo Mode Banner Component
function DemoModeBanner({ isDemoMode, demoResetInterval }) {
  if (!isDemoMode) return null;

  return (
    <div className="sticky top-0 left-0 right-0 z-50 bg-amber-100 dark:bg-amber-900 border-b-2 border-amber-400 dark:border-amber-700 px-4 py-3 text-center">
      <div className="flex items-center justify-center gap-3">
        <span className="text-2xl">🛠️</span>
        <span className="font-semibold text-amber-900 dark:text-amber-100">
          Demo Mode
        </span>
        <span className="text-sm text-amber-700 dark:text-amber-300">
          All changes reset every {demoResetInterval} minutes
        </span>
      </div>
    </div>
  );
}

export default DemoModeBanner;
