import React from 'react';
import { Upload } from 'lucide-react';

function ImageUpload({ label, image, onUpload, onRemove, isBanner, disabled = false }) {
  return (
    <section>
      <h3 className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-3">{label}</h3>
      <div className={`relative ${isBanner ? 'w-full h-32' : 'w-24 h-24'} rounded-input bg-surface dark:bg-surface-dark border-thick border-dashed border-border dark:border-border-dark flex items-center justify-center overflow-hidden group ${disabled ? 'opacity-50 cursor-not-allowed' : 'hover:border-border-dark dark:hover:border-border-dark'} transition-colors`}>
        {image ? <img src={image} className="w-full h-full object-cover" alt="upload" /> : <div className="text-center text-text-muted-subtle dark:text-text-muted-dark pointer-events-none"><Upload className="w-6 h-6 mx-auto mb-1" /><span className="text-xs">Upload</span></div>}
        <input type="file" accept="image/*" onChange={onUpload} disabled={disabled} className="absolute inset-0 opacity-0 cursor-pointer appearance-none bg-transparent focus:outline-none disabled:cursor-not-allowed" />
      </div>
      {image && !disabled && <button onClick={onRemove} className="mt-2 text-sm text-red-500 dark:text-red-400 font-medium hover:text-red-600 dark:hover:text-red-300">Remove</button>}
    </section>
  );
}

export default ImageUpload;
