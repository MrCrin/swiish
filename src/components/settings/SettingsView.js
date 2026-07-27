import React, { useState, useEffect } from 'react';
import { ArrowLeft, RefreshCw, Check, Save, ChevronUp, ChevronDown, Plus, Edit3 } from 'lucide-react';
import { API_ENDPOINT } from '../../constants/app';
import { THEME_PRESETS, applyThemeCssVars } from '../../constants/theme';
import { extractBaseColorFromGradient, getTailwindColorHex, getComplementaryColor } from '../../constants/colors';
import Toggle from '../common/Toggle';
import Input from '../common/Input';
import ColorSelector from '../common/ColorSelector';

function SettingsView({ settings, setSettings, onBack, onSave, apiCall, showAlert, showConfirm }) {
  // Initialize local settings with extracted base colors from existing data
  const initializeColorData = (colors) => {
    return colors.map(color => {
      let hexBase, baseColor, colorType;

      // Determine if this is a standard color (has Tailwind gradient or baseColor) or custom hex
      const hasValidTailwindGradient = color.gradient && typeof color.gradient === 'string' && color.gradient.startsWith('from-');
      const hasHexBase = color.hexBase && typeof color.hexBase === 'string' && color.hexBase.startsWith('#');

      if (hasValidTailwindGradient) {
        // Convert from Tailwind gradient to hex
        const extracted = extractBaseColorFromGradient(color.gradient);
        if (extracted) {
          baseColor = extracted.baseColor;
          hexBase = getTailwindColorHex(extracted.baseColor, 600); // Always use shade 600
          colorType = 'standard';
        } else {
          // Fallback if extraction fails
          baseColor = color.baseColor || 'indigo';
          hexBase = hasHexBase ? color.hexBase : getTailwindColorHex(baseColor, 600);
          colorType = color.colorType === 'custom' ? 'custom' : 'standard';
        }
      } else if (hasHexBase) {
        // Has hexBase - determine if standard or custom
        if (color.baseColor && color.colorType !== 'custom') {
          // Standard color with hexBase
          baseColor = color.baseColor;
          hexBase = color.hexBase;
          colorType = 'standard';
        } else {
          // Custom hex color
          baseColor = null;
          hexBase = color.hexBase;
          colorType = 'custom';
        }
      } else if (color.gradientStyle) {
        // Has gradientStyle but no hexBase - extract from gradientStyle or use default
        baseColor = null;
        hexBase = '#4f46e5'; // Default
        colorType = 'custom';
      } else {
        // Fallback - treat as standard with default
        baseColor = color.baseColor || 'indigo';
        hexBase = getTailwindColorHex(baseColor, 600);
        colorType = color.colorType === 'custom' ? 'custom' : 'standard';
      }

      // Always auto-generate complementary secondary color
      const complementaryColor = baseColor ? getComplementaryColor(baseColor) : null;
      const hexSecondary = color.hexSecondary || (complementaryColor ? getTailwindColorHex(complementaryColor, 600) : hexBase);

      // Generate all inline styles
      const gradientStyle = `linear-gradient(135deg, ${hexBase}, ${hexSecondary})`;
      const buttonStyle = hexBase;
      const linkStyle = hexBase;
      const textStyle = hexBase;

      // Build clean hex-only color object
      return {
        name: color.name,
        colorType: colorType,
        baseColor: baseColor, // null for custom, Tailwind name for standard
        hexBase: hexBase,
        hexSecondary: hexSecondary,
        gradientStyle: gradientStyle,
        buttonStyle: buttonStyle,
        linkStyle: linkStyle,
        textStyle: textStyle
      };
    });
  };

  const [localSettings, setLocalSettings] = useState({
    ...settings,
    theme_colors: initializeColorData(settings.theme_colors || []),
    theme_variant: settings.theme_variant || 'default',
    // Initialize override toggles - default to true if undefined, but preserve false
    allow_theme_customisation: settings.allow_theme_customisation !== undefined ? Boolean(settings.allow_theme_customisation) : true,
    allow_image_customisation: settings.allow_image_customisation !== undefined ? Boolean(settings.allow_image_customisation) : true,
    allow_links_customisation: settings.allow_links_customisation !== undefined ? Boolean(settings.allow_links_customisation) : true,
    allow_privacy_customisation: settings.allow_privacy_customisation !== undefined ? Boolean(settings.allow_privacy_customisation) : true
  });
  const [editingColorIndex, setEditingColorIndex] = useState(null);
  const [isSaving, setIsSaving] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [isOrganisationNameOpen, setIsOrganisationNameOpen] = useState(false);
  const [isCustomizationControlsOpen, setIsCustomizationControlsOpen] = useState(false);
  const [isThemeColorsOpen, setIsThemeColorsOpen] = useState(false);
  const [isAppThemesOpen, setIsAppThemesOpen] = useState(false);

  const applyThemePreset = (variant) => {
    setEditingColorIndex(null);
    const preset = THEME_PRESETS?.[variant];
    setLocalSettings(prev => ({
      ...prev,
      theme_variant: preset ? variant : 'custom',
      theme_colors: preset ? initializeColorData(preset) : prev.theme_colors
    }));
  };

  // Re-initialize when settings prop changes
  useEffect(() => {
    setLocalSettings({
      ...settings,
      theme_colors: initializeColorData(settings.theme_colors || []),
      theme_variant: settings.theme_variant || localSettings.theme_variant || 'swiish',
      // Initialize override toggles - default to true if undefined, but preserve false
      allow_theme_customisation: settings.allow_theme_customisation !== undefined ? Boolean(settings.allow_theme_customisation) : true,
      allow_image_customisation: settings.allow_image_customisation !== undefined ? Boolean(settings.allow_image_customisation) : true,
      allow_links_customisation: settings.allow_links_customisation !== undefined ? Boolean(settings.allow_links_customisation) : true,
      allow_privacy_customisation: settings.allow_privacy_customisation !== undefined ? Boolean(settings.allow_privacy_customisation) : true
    });
  }, [settings]);

  // Apply app theme variant class to body for CSS overrides (swiish|minimal|custom)
  useEffect(() => {
    const variant = localSettings.theme_variant || settings.theme_variant || 'swiish';
    document.body.classList.remove('theme-swiish', 'theme-minimal', 'theme-custom');
    document.body.classList.add(`theme-${variant}`);
    applyThemeCssVars(variant);
  }, [localSettings.theme_variant, settings.theme_variant]);

  const handleSave = async () => {
    setIsSaving(true);
    const startTime = Date.now();
    try {
      // Save hex-only color structure
      const colorsToSave = localSettings.theme_colors.map(color => {
        return {
          name: color.name,
          colorType: color.colorType || 'standard',
          baseColor: color.baseColor || null, // null for custom, Tailwind name for standard
          hexBase: color.hexBase || '#4f46e5',
          hexSecondary: color.hexSecondary || color.hexBase || '#4f46e5',
          gradientStyle: color.gradientStyle || `linear-gradient(135deg, ${color.hexBase || '#4f46e5'}, ${color.hexSecondary || color.hexBase || '#4f46e5'})`,
          buttonStyle: color.buttonStyle || color.hexBase || '#4f46e5',
          linkStyle: color.linkStyle || color.hexBase || '#4f46e5',
          textStyle: color.textStyle || color.hexBase || '#4f46e5'
        };
      });

      const res = await apiCall(`${API_ENDPOINT}/admin/settings`, {
        method: 'POST',
        body: JSON.stringify({
          default_organisation: localSettings.default_organisation,
          theme_colors: colorsToSave,
          theme_variant: localSettings.theme_variant || 'swiish',
          allow_theme_customisation: Boolean(localSettings.allow_theme_customisation),
          allow_image_customisation: Boolean(localSettings.allow_image_customisation),
          allow_links_customisation: Boolean(localSettings.allow_links_customisation),
          allow_privacy_customisation: Boolean(localSettings.allow_privacy_customisation)
        })
      });

      // Ensure at least 500ms has passed
      const elapsedTime = Date.now() - startTime;
      if (elapsedTime < 500) {
        await new Promise(resolve => setTimeout(resolve, 500 - elapsedTime));
      }

      if (res.ok) {
        // Refetch from server to get the latest saved data
        setIsSuccess(true);
        setTimeout(() => setIsSuccess(false), 2000);
        await onSave();
      } else {
        const errorData = await res.json().catch(() => ({}));
        console.error('Save failed:', errorData);
        if (showAlert) showAlert('Failed to save settings', 'error');
      }
    } catch (e) {
      if (showAlert) showAlert('Error saving settings', 'error');
    } finally {
      setIsSaving(false);
    }
  };

  const addColor = () => {
    const baseColor = 'indigo';
    const hexBase = getTailwindColorHex(baseColor, 600);
    const complementary = getComplementaryColor(baseColor);
    const hexSecondary = getTailwindColorHex(complementary, 600);

    const newColor = {
      name: `color${localSettings.theme_colors.length + 1}`,
      colorType: 'standard',
      baseColor: baseColor,
      hexBase: hexBase,
      hexSecondary: hexSecondary,
      gradientStyle: `linear-gradient(135deg, ${hexBase}, ${hexSecondary})`,
      buttonStyle: hexBase,
      linkStyle: hexBase,
      textStyle: hexBase
    };
    setLocalSettings(prev => {
      const newColors = [...prev.theme_colors, newColor];
      setEditingColorIndex(newColors.length - 1);
      return {
        ...prev,
        theme_colors: newColors,
        theme_variant: 'custom'
      };
    });
  };

  const updateColor = (colorIndex, field, value) => {
    setLocalSettings(prev => {
      const updated = prev.theme_colors.map((c, idx) => {
        if (idx === colorIndex) {
          const updatedColor = { ...c, [field]: value };
          const currentColorType = updatedColor.colorType || c.colorType || 'standard';

          // Handle colorType changes
          if (field === 'colorType') {
            if (value === 'standard' && !updatedColor.baseColor) {
              // Switching to standard - set default baseColor if missing
              updatedColor.baseColor = c.baseColor || 'indigo';
              updatedColor.hexBase = c.hexBase || getTailwindColorHex(updatedColor.baseColor, 600);
            } else if (value === 'custom') {
              // Switching to custom - clear baseColor
              updatedColor.baseColor = null;
            }
          }

          // For standard colors: when baseColor changes, update hexBase
          if (currentColorType === 'standard' && field === 'baseColor') {
            updatedColor.hexBase = getTailwindColorHex(value, 600);
          }

          // For custom colors: when hexBase changes, ensure colorType is custom
          if (field === 'hexBase') {
            if (currentColorType !== 'custom') {
              updatedColor.colorType = 'custom';
              updatedColor.baseColor = null;
            }
          }

          // Handle hexBase
          let hexBase = updatedColor.hexBase || c.hexBase;
          let baseColor = updatedColor.baseColor || c.baseColor;

          // If hexBase is missing, generate it
          if (!hexBase) {
            if (baseColor) {
              hexBase = getTailwindColorHex(baseColor, 600);
              updatedColor.hexBase = hexBase;
            } else {
              hexBase = '#4f46e5'; // Default
              updatedColor.hexBase = hexBase;
            }
          }

          // Handle hexSecondary
          let hexSecondary;

          if (currentColorType === 'standard') {
            // Standard colors always use auto-complementary
            const complementaryColor = baseColor ? getComplementaryColor(baseColor) : null;
            hexSecondary = complementaryColor ? getTailwindColorHex(complementaryColor, 600) : hexBase;
            updatedColor.hexSecondary = hexSecondary;
          } else if (currentColorType === 'custom') {
            // Custom colors: allow manual setting
            if (field === 'hexSecondary') {
              // User is manually setting hexSecondary
              hexSecondary = value || null;
              updatedColor.hexSecondary = hexSecondary;
            } else if (field === 'baseColor' || field === 'hexBase' || field === 'colorType') {
              // When baseColor/hexBase changes, only auto-generate if hexSecondary is not manually set
              const existingHexSecondary = c.hexSecondary;
              if (!existingHexSecondary || existingHexSecondary === '') {
                // Auto-generate complementary
                const complementaryColor = baseColor ? getComplementaryColor(baseColor) : null;
                hexSecondary = complementaryColor ? getTailwindColorHex(complementaryColor, 600) : hexBase;
                updatedColor.hexSecondary = hexSecondary;
              } else {
                // Keep existing manual value
                hexSecondary = existingHexSecondary;
                updatedColor.hexSecondary = hexSecondary;
              }
            } else {
              // Keep existing value
              hexSecondary = updatedColor.hexSecondary || c.hexSecondary || hexBase;
              updatedColor.hexSecondary = hexSecondary;
            }
          } else {
            // Fallback
            hexSecondary = updatedColor.hexSecondary || c.hexSecondary || hexBase;
            updatedColor.hexSecondary = hexSecondary;
          }

          // Always regenerate inline styles when relevant fields change
          if (field === 'baseColor' || field === 'colorType' || field === 'hexBase' || field === 'hexSecondary') {
            const finalHexSecondary = hexSecondary || hexBase;
            updatedColor.gradientStyle = `linear-gradient(135deg, ${hexBase}, ${finalHexSecondary})`;
            updatedColor.buttonStyle = hexBase;
            updatedColor.linkStyle = hexBase;
            updatedColor.textStyle = hexBase;
          }

          return updatedColor;
        }
        return c;
      });
      return { ...prev, theme_colors: updated, theme_variant: 'custom' };
    });
  };

  const removeColor = (colorIndex) => {
    if (localSettings.theme_colors.length <= 1) {
      if (showAlert) showAlert('You must have at least one color', 'error');
      return;
    }
    const colorName = localSettings.theme_colors[colorIndex]?.name;
    if (showConfirm) {
      showConfirm(
        `Delete color "${colorName}"?`,
        () => {
          setLocalSettings(prev => ({
            ...prev,
            theme_colors: prev.theme_colors.filter((c, idx) => idx !== colorIndex),
            theme_variant: 'custom'
          }));
          if (editingColorIndex === colorIndex) {
            setEditingColorIndex(null);
          } else if (editingColorIndex !== null && editingColorIndex > colorIndex) {
            // Adjust index if we deleted a color before the one being edited
            setEditingColorIndex(editingColorIndex - 1);
          }
        },
        'Delete Color',
        'Delete',
        'Cancel'
      );
    }
  };

  return (
    <div className="min-h-screen bg-main dark:bg-main-dark bg-main-texture flex flex-col lg:flex-row">
      <div className="w-full lg:w-1/2 bg-card dark:bg-card-dark border-r border-border dark:border-border-dark h-auto lg:h-screen overflow-y-auto flex flex-col">
        <div className="p-6 border-b border-border-subtle dark:border-border-dark flex items-center justify-between bg-card dark:bg-card-dark sticky top-0 z-10">
          <div className="flex items-center gap-4">
            <button onClick={onBack} className="p-2 hover:bg-surface dark:hover:bg-surface-dark rounded-full text-text-muted dark:text-text-muted-dark">
              <ArrowLeft className="w-5 h-5"/>
            </button>
            <div>
              <h1 className="text-xl font-bold text-text-primary dark:text-text-primary-dark">Organisation Settings</h1>
            </div>
          </div>
          <button
            onClick={handleSave}
            disabled={isSaving}
            className="px-5 py-2 bg-confirm dark:bg-confirm-dark text-confirm-text dark:text-confirm-text-dark rounded-full text-sm font-bold flex items-center gap-2 hover:bg-confirm-hover dark:hover:bg-confirm-hover-dark transition-colors disabled:opacity-50"
          >
            {isSaving ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : isSuccess ? (
              <Check className="w-4 h-4 text-green-500" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            {isSaving ? 'Saving...' : 'Save'}
          </button>
        </div>

        <div className="flex-1 p-6 space-y-6">
          <div className="space-y-6">
            {/* Organisation Name Section */}
            <div>
              <button
                onClick={() => setIsOrganisationNameOpen(!isOrganisationNameOpen)}
                className="w-full flex items-center justify-between p-4 bg-surface dark:bg-card-dark/50 rounded-input hover:bg-surface dark:hover:bg-card-dark transition-colors"
              >
                <div className="text-left">
                  <h2 className="text-base font-semibold text-text-primary dark:text-text-primary-dark">Organisation Name</h2>
                  <p className="text-sm text-text-secondary dark:text-text-muted-dark mt-1">This organisation name will be applied to all cards in your organisation. Users cannot change this.</p>
                </div>
                {isOrganisationNameOpen ? (
                  <ChevronUp className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                )}
              </button>

              {isOrganisationNameOpen && (
                <div className="mt-4 p-4 bg-surface dark:bg-card-dark/50 rounded-input">
                  <input
                    type="text"
                    value={localSettings.default_organisation || ''}
                    onChange={(e) => setLocalSettings(prev => ({ ...prev, default_organisation: e.target.value }))}
                    className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-input-bg dark:bg-input-bg-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark"
                    placeholder="Organisation Name"
                  />
                </div>
              )}
            </div>

            <div className="h-px bg-surface dark:bg-surface-dark" />

            {/* Organization Override Toggles */}
            <div className="space-y-6">
              <button
                onClick={() => setIsCustomizationControlsOpen(!isCustomizationControlsOpen)}
                className="w-full flex items-center justify-between p-4 bg-surface dark:bg-card-dark/50 rounded-input hover:bg-surface dark:hover:bg-card-dark transition-colors"
              >
                <div className="text-left">
                  <h2 className="text-base font-semibold text-text-primary dark:text-text-primary-dark">User Customisation Controls</h2>
                  <p className="text-sm text-text-secondary dark:text-text-muted-dark mt-1">Control what users in your organisation can customise on their cards.</p>
                </div>
                {isCustomizationControlsOpen ? (
                  <ChevronUp className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                )}
              </button>

              {isCustomizationControlsOpen && (
                <div className="mt-4 space-y-4">
                  {/* Theme Customization Group */}
              <div className="bg-surface dark:bg-card-dark/50 rounded-input p-5 space-y-4">
                <div>
                  <h3 className="text-sm font-semibold text-text-primary dark:text-text-primary-dark mb-2">Theme Customisation</h3>
                  <p className="text-xs text-text-secondary dark:text-text-muted-dark mb-4">Control whether users can choose theme colors for their cards.</p>
                </div>
                <Toggle
                  label="Allow users to choose theme colors"
                  description="When enabled, users can select from your organisation's theme colour palette. When disabled, cards will use the first colour in your palette."
                  checked={localSettings.allow_theme_customisation === true}
                  onChange={(checked) => setLocalSettings(prev => ({ ...prev, allow_theme_customisation: checked }))}
                />
              </div>

              {/* Image Customization Group */}
              <div className="bg-surface dark:bg-card-dark/50 rounded-input p-5 space-y-4">
                <div>
                  <h3 className="text-sm font-semibold text-text-primary dark:text-text-primary-dark mb-2">Image Customisation</h3>
                  <p className="text-xs text-text-secondary dark:text-text-muted-dark mb-4">Control whether users can upload custom avatars and banner images.</p>
                </div>
                <Toggle
                  label="Allow users to upload custom avatars and banners"
                  description="When enabled, users can upload their own images. When disabled, image uploads will be blocked."
                  checked={localSettings.allow_image_customisation === true}
                  onChange={(checked) => setLocalSettings(prev => ({ ...prev, allow_image_customisation: checked }))}
                />
              </div>

              {/* Links Customization Group */}
              <div className="bg-surface dark:bg-card-dark/50 rounded-input p-5 space-y-4">
                <div>
                  <h3 className="text-sm font-semibold text-text-primary dark:text-text-primary-dark mb-2">Links Customisation</h3>
                  <p className="text-xs text-text-secondary dark:text-text-muted-dark mb-4">Control whether users can add custom links to their cards.</p>
                </div>
                <Toggle
                  label="Allow users to add custom links"
                  description="When enabled, users can add custom links to their cards. When disabled, the links section will be locked."
                  checked={localSettings.allow_links_customisation === true}
                  onChange={(checked) => setLocalSettings(prev => ({ ...prev, allow_links_customisation: checked }))}
                />
              </div>

              {/* Privacy Settings Group */}
              <div className="bg-surface dark:bg-card-dark/50 rounded-input p-5 space-y-4">
                <div>
                  <h3 className="text-sm font-semibold text-text-primary dark:text-text-primary-dark mb-2">Privacy Settings</h3>
                  <p className="text-xs text-text-secondary dark:text-text-muted-dark mb-4">Control whether users can change privacy settings on their cards.</p>
                </div>
                <Toggle
                  label="Allow users to change privacy settings"
                  description="When enabled, users can modify privacy options (require interaction, obfuscation, block robots). When disabled, privacy settings will be locked to organisation defaults."
                  checked={localSettings.allow_privacy_customisation === true}
                  onChange={(checked) => setLocalSettings(prev => ({ ...prev, allow_privacy_customisation: checked }))}
                />
              </div>
                </div>
              )}
            </div>

            <div className="h-px bg-surface dark:bg-surface-dark" />

            {/* App Themes */}
            <div>
              <button
                onClick={() => setIsAppThemesOpen(!isAppThemesOpen)}
                className="w-full flex items-center justify-between p-4 bg-surface dark:bg-card-dark/50 rounded-input hover:bg-surface dark:hover:bg-card-dark transition-colors"
              >
                <div className="text-left">
                  <h2 className="text-base font-semibold text-text-primary dark:text-text-primary-dark">App Themes</h2>
                  <p className="text-sm text-text-secondary dark:text-text-muted-dark mt-1">Choose the look for the app UI (backgrounds, chrome, buttons).</p>
                </div>
                {isAppThemesOpen ? (
                  <ChevronUp className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                )}
              </button>

              {isAppThemesOpen && (
                <div className="mt-4 space-y-3">
                  {[
                    { id: 'swiish', title: 'Swiish', desc: 'Original Swiish theme with colors and textures.' },
                    { id: 'minimal', title: 'Minimal', desc: 'Black/white, few grays, no textures, border-only accents.' },
                  ].map(opt => (
                    <label
                      key={opt.id}
                      className="flex items-start gap-3 p-3 rounded-input border border-border dark:border-border-dark bg-surface dark:bg-surface-dark hover:bg-card dark:hover:bg-card-dark transition-colors cursor-pointer"
                    >
                      <input
                        type="radio"
                        name="app-theme"
                        className="mt-1"
                        value={opt.id}
                        checked={(localSettings.theme_variant || 'swiish') === opt.id}
                        onChange={(e) => applyThemePreset(e.target.value)}
                      />
                      <div>
                        <div className="font-medium text-text-primary dark:text-text-primary-dark">{opt.title}</div>
                        <p className="text-sm text-text-secondary dark:text-text-muted-dark">{opt.desc}</p>
                      </div>
                    </label>
                  ))}
                </div>
              )}
            </div>

            <div className="h-px bg-surface dark:bg-surface-dark" />

            {/* Profile Colors */}
            <div>
              <button
                onClick={() => setIsThemeColorsOpen(!isThemeColorsOpen)}
                className="w-full flex items-center justify-between p-4 bg-surface dark:bg-card-dark/50 rounded-input hover:bg-surface dark:hover:bg-card-dark transition-colors"
              >
                <div className="text-left">
                  <h2 className="text-base font-semibold text-text-primary dark:text-text-primary-dark">Profile Colors</h2>
                  <p className="text-sm text-text-secondary dark:text-text-muted-dark mt-1">Manage the color palette available for user cards.</p>
                </div>
                {isThemeColorsOpen ? (
                  <ChevronUp className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-text-secondary dark:text-text-muted-dark" />
                )}
              </button>

              {isThemeColorsOpen && (
                <div className="mt-4 space-y-4">
                  <div className="flex justify-end">
                      <button
                        onClick={addColor}
                        className="text-sm font-bold text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 flex items-center gap-1 px-4 py-2 bg-indigo-50 dark:bg-indigo-900/30 rounded-badge hover:bg-indigo-100 dark:hover:bg-indigo-900/50 transition-colors"
                      >
                        <Plus className="w-4 h-4" /> Add Color
                      </button>
                    </div>

              <div className="space-y-4">
                {localSettings.theme_colors?.map((color, index) => (
                  <div key={index} className="bg-surface dark:bg-surface-dark p-4 rounded-input border border-border dark:border-border-dark">
                    {editingColorIndex === index ? (
                      <div className="space-y-4">
                        <div className="flex justify-between items-center">
                          <h4 className="font-medium text-text-primary dark:text-text-primary-dark">Editing: {color.name}</h4>
                          <div className="flex gap-2">
                            <button
                              onClick={() => setEditingColorIndex(null)}
                              className="px-3 py-1 text-sm bg-card dark:bg-surface-dark border border-border dark:border-border-dark rounded-button hover:bg-surface dark:hover:bg-surface-dark text-text-primary dark:text-text-primary-dark"
                            >
                              Done
                            </button>
                            <button
                              onClick={() => removeColor(index)}
                              className="px-3 py-1 text-sm bg-error-bg dark:bg-error-bg-dark text-error dark:text-error-text-dark border border-error-border dark:border-error-border-dark rounded-badge hover:bg-error-bg dark:hover:bg-error-bg-dark"
                            >
                              Delete
                            </button>
                          </div>
                        </div>

                        <Input
                          label="Color Name"
                          value={color.name}
                          onChange={(v) => updateColor(index, 'name', v)}
                        />

                        <div>
                          <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Color Type</label>
                          <div className="flex gap-2">
                            <button
                              onClick={() => updateColor(index, 'colorType', 'standard')}
                              className={`flex-1 px-4 py-2 rounded-button border transition-all ${
                                (color.colorType || 'standard') === 'standard'
                                  ? 'bg-indigo-50 dark:bg-indigo-900/30 border-indigo-500 dark:border-indigo-400 text-indigo-700 dark:text-indigo-300 font-medium'
                                  : 'bg-card dark:bg-surface-dark border-border dark:border-border-dark text-text-secondary dark:text-text-secondary-dark hover:bg-surface dark:hover:bg-surface-dark'
                              }`}
                            >
                              Standard Colors
                            </button>
                            <button
                              onClick={() => updateColor(index, 'colorType', 'custom')}
                              className={`flex-1 px-4 py-2 rounded-button border transition-all ${
                                color.colorType === 'custom'
                                  ? 'bg-indigo-50 dark:bg-indigo-900/30 border-indigo-500 dark:border-indigo-400 text-indigo-700 dark:text-indigo-300 font-medium'
                                  : 'bg-card dark:bg-surface-dark border-border dark:border-border-dark text-text-secondary dark:text-text-secondary-dark hover:bg-surface dark:hover:bg-surface-dark'
                              }`}
                            >
                              Custom Colours
                            </button>
                          </div>
                        </div>

                        {(color.colorType || 'standard') === 'standard' ? (
                          <>
                            <ColorSelector
                              label="Base Color"
                              selectedColor={color.baseColor || 'indigo'}
                              onSelect={(selected) => updateColor(index, 'baseColor', selected)}
                            />
                            <p className="text-xs text-text-muted dark:text-text-muted-dark">Secondary: Auto (complementary)</p>
                          </>
                        ) : (
                          <>
                            <div>
                              <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Base Color</label>
                              <div className="flex gap-2 items-center">
                                <input
                                  type="color"
                                  value={color.hexBase || '#4f46e5'}
                                  onChange={(e) => updateColor(index, 'hexBase', e.target.value)}
                                  className="w-16 h-10 rounded-input border border-border dark:border-border-dark cursor-pointer"
                                />
                                <input
                                  type="text"
                                  value={color.hexBase || '#4f46e5'}
                                  onChange={(e) => updateColor(index, 'hexBase', e.target.value)}
                                  placeholder="#4f46e5"
                                  className="flex-1 px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-card dark:bg-surface-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark font-mono text-sm"
                                />
                              </div>
                            </div>

                            <div>
                              <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Secondary Color (optional)</label>
                              <div className="flex gap-2 items-center">
                                <input
                                  type="color"
                                  value={color.hexSecondary || color.hexBase || '#7c3aed'}
                                  onChange={(e) => updateColor(index, 'hexSecondary', e.target.value)}
                                  className="w-16 h-10 rounded-input border border-border dark:border-border-dark cursor-pointer"
                                />
                                <input
                                  type="text"
                                  value={color.hexSecondary || ''}
                                  onChange={(e) => updateColor(index, 'hexSecondary', e.target.value || null)}
                                  placeholder="Leave blank for auto (complementary)"
                                  className="flex-1 px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-card dark:bg-surface-dark text-text-primary dark:text-text-primary-dark focus:outline-none focus:ring-2 focus:ring-2 focus:ring-focus-ring dark:focus:ring-focus-ring-dark focus:border-action dark:focus:border-action-dark font-mono text-sm"
                                />
                              </div>
                              <p className="text-xs text-text-muted dark:text-text-muted-dark mt-1">Leave blank to use auto (complementary) color</p>
                            </div>
                          </>
                        )}

                        {/* Preview of generated gradient */}
                        <div>
                          <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark mb-2 block">Preview</label>
                          <div
                            className="w-full h-16 rounded-container overflow-hidden"
                            style={{ background: color.gradientStyle || 'linear-gradient(135deg, #4f46e5, #7c3aed)' }}
                          />
                        </div>

                        {/* Collapsible advanced view */}
                        <details className="text-sm">
                          <summary className="cursor-pointer text-text-secondary dark:text-text-muted-dark hover:text-text-primary dark:hover:text-text-primary-dark font-medium mb-2">
                            Advanced: Generated Styles
                          </summary>
                          <div className="bg-card dark:bg-surface-dark p-3 rounded-container border border-border dark:border-border-dark space-y-2 text-xs font-mono">
                            <div><span className="text-text-muted dark:text-text-muted-dark">Gradient Style:</span> <span className="text-text-primary dark:text-text-primary-dark">{color.gradientStyle || 'N/A'}</span></div>
                            <div><span className="text-text-muted dark:text-text-muted-dark">Button Style:</span> <span className="text-text-primary dark:text-text-primary-dark">{color.buttonStyle || 'N/A'}</span></div>
                            <div><span className="text-text-muted dark:text-text-muted-dark">Link Style:</span> <span className="text-text-primary dark:text-text-primary-dark">{color.linkStyle || 'N/A'}</span></div>
                            <div><span className="text-text-muted dark:text-text-muted-dark">Text Style:</span> <span className="text-text-primary dark:text-text-primary-dark">{color.textStyle || 'N/A'}</span></div>
                          </div>
                        </details>
                      </div>
                    ) : (
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                          <div
                            className="w-12 h-12 rounded-full"
                            style={{ background: color.gradientStyle || 'linear-gradient(135deg, #4f46e5, #7c3aed)' }}
                          />
                          <div>
                            <div className="font-medium text-text-primary dark:text-text-primary-dark">
                              {color.baseColor ? (color.baseColor.charAt(0).toUpperCase() + color.baseColor.slice(1)) : color.name}
                            </div>
                            <div className="text-xs text-text-muted dark:text-text-muted-dark">
                              {color.baseColor ? 'Standard' : 'Custom'} (Secondary: Auto)
                            </div>
                          </div>
                        </div>
                        <button
                          onClick={() => setEditingColorIndex(index)}
                          className="px-3 py-1 text-sm bg-card dark:bg-surface-dark border border-border dark:border-border-dark rounded-button hover:bg-surface dark:hover:bg-surface-dark flex items-center gap-1 text-text-primary dark:text-text-primary-dark"
                        >
                          <Edit3 className="w-3 h-3" /> Edit
                        </button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="hidden lg:flex w-1/2 bg-main dark:bg-main-dark items-center justify-center p-10">
        <div className="bg-card dark:bg-card-dark rounded-card p-8 shadow-lg max-w-md w-full border border-border dark:border-border-dark relative z-10 isolate">
          <h3 className="text-lg font-bold text-text-primary dark:text-text-primary-dark mb-4">Preview</h3>
          <div className="space-y-4">
            <div>
              <div className="text-sm text-text-secondary dark:text-text-muted-dark mb-2">Default Organisation:</div>
              <div className="font-medium text-text-primary dark:text-text-primary-dark">{localSettings.default_organisation || 'Not set'}</div>
            </div>
            <div>
              <div className="text-sm text-text-secondary dark:text-text-muted-dark mb-3">Color Effects:</div>
              {(() => {
                const previewColor = editingColorIndex !== null && localSettings.theme_colors?.[editingColorIndex]
                  ? localSettings.theme_colors[editingColorIndex]
                  : localSettings.theme_colors?.[0];

                return (
                  <div className="space-y-3">
                    {/* Text example */}
                    <div>
                      <div className="text-xs text-text-muted dark:text-text-muted-dark mb-1">Text</div>
                      <div
                        className="text-lg font-medium"
                        style={{ color: previewColor?.textStyle || '#4f46e5' }}
                      >
                        Example Text
                      </div>
                    </div>

                    {/* Link example */}
                    <div>
                      <div className="text-xs text-text-muted dark:text-text-muted-dark mb-1">Link</div>
                      <a
                        href="#"
                        className="inline-block px-4 py-2 rounded-input border border-border dark:border-border-dark transition-all hover:opacity-80"
                        style={{ color: previewColor?.linkStyle || '#4f46e5' }}
                        onClick={(e) => e.preventDefault()}
                      >
                        Example Link
                      </a>
                    </div>

                    {/* Button example */}
                    <div>
                      <div className="text-xs text-text-muted dark:text-text-muted-dark mb-1">Button</div>
                      <button
                        className="px-4 py-2 rounded-full font-medium text-white shadow-md transition-transform active:scale-[0.98]"
                        style={{ backgroundColor: previewColor?.buttonStyle || '#4f46e5' }}
                      >
                        Example Button
                      </button>
                    </div>

                    {/* Gradient background example */}
                    <div>
                      <div className="text-xs text-text-muted dark:text-text-muted-dark mb-1">Gradient Background</div>
                      <div
                        className="w-full h-12 rounded-container overflow-hidden"
                        style={{ background: previewColor?.gradientStyle || 'linear-gradient(135deg, #4f46e5, #7c3aed)' }}
                      />
                    </div>
                  </div>
                );
              })()}
            </div>
          </div>
        </div>
      </div>
      <div className="fixed bottom-4 right-4 z-10 text-center group">
        <div className="flex justify-center">
          <img src="/graphics/Swiish_Logo.svg" alt="Swiish" className="h-4 w-auto dark:hidden swiish-logo" />
          <img src="/graphics/Swiish_Logo_DarkBg.svg" alt="Swiish" className="h-4 w-auto hidden dark:block swiish-logo" />
        </div>
      </div>
    </div>
  );
}

export default SettingsView;
