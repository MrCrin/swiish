import React, { useState } from 'react';
import PhoneInput from 'react-phone-number-input';
import 'react-phone-number-input/style.css';
import flags from 'country-flag-icons/react/3x2';
import {
  Mail, Globe, Linkedin, Twitter, Instagram, Github, Lock, Plus, Check,
  X, ChevronUp, ChevronDown, GripVertical, ArrowLeft, RefreshCw, Save,
  Link as LinkIcon
} from 'lucide-react';
import { DndContext, PointerSensor, closestCenter, useSensor, useSensors } from '@dnd-kit/core';
import { SortableContext, verticalListSortingStrategy, arrayMove } from '@dnd-kit/sortable';
import { API_ENDPOINT } from '../../constants/app';
import { ICON_MAP } from '../../constants/icons';
import Input from '../common/Input';
import TextArea from '../common/TextArea';
import Toggle from '../common/Toggle';
import ImageUpload from '../common/ImageUpload';
import LockedOption from '../common/LockedOption';
import SortableLinkItem from './SortableLinkItem';
import CardDisplay from '../public-card/CardDisplay';

function EditorView({ data, setData, onBack, onSave, slug, settings, csrfToken, showAlert, darkMode, toggleDarkMode, isSaving, isSuccess, onLogout }) {
  const [activeTab, setActiveTab] = useState('details');
  const [isUploading, setIsUploading] = useState(false);
  const sensors = useSensors(
    useSensor(PointerSensor, {
      activationConstraint: { distance: 5 }
    })
  );

  const handleInputChange = (section, field, value) => {
    setData(prev => ({ ...prev, [section]: { ...prev[section], [field]: value } }));
  };

  const handleImageUpload = async (type, e) => {
    const file = e.target.files[0];
    if (!file) return;

    setIsUploading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(`${API_ENDPOINT}/upload`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'X-CSRF-Token': csrfToken
        },
        body: formData
      });

      if (res.ok) {
        const { url } = await res.json();
        setData(prev => ({ ...prev, images: { ...prev.images, [type]: url } }));
      } else {
        if (showAlert) showAlert('Upload failed', 'error');
      }
    } catch (error) {
      if (showAlert) showAlert('Upload error', 'error');
    } finally {
      setIsUploading(false);
    }
  };

  const addLink = () => {
    const newLink = { id: Date.now(), title: '', url: '', icon: 'link' };
    setData(prev => ({ ...prev, links: [...prev.links, newLink] }));
  };
  const removeLink = (id) => {
    setData(prev => ({ ...prev, links: prev.links.filter(l => l.id !== id) }));
  };
  const updateLink = (id, field, value) => {
    setData(prev => ({ ...prev, links: prev.links.map(l => l.id === id ? { ...l, [field]: value } : l) }));
  };

  const reorderLinks = (oldIndex, newIndex) => {
    if (oldIndex === newIndex) return;
    setData(prev => ({ ...prev, links: arrayMove(prev.links, oldIndex, newIndex) }));
  };

  const moveLinkUp = (index) => {
    if (index <= 0) return;
    reorderLinks(index, index - 1);
  };

  const moveLinkDown = (index) => {
    if (index >= data.links.length - 1) return;
    reorderLinks(index, index + 1);
  };

  const handleDragEnd = (event) => {
    const { active, over } = event;
    if (!over || active.id === over.id) return;
    const oldIndex = data.links.findIndex(link => link.id === active.id);
    const newIndex = data.links.findIndex(link => link.id === over.id);
    if (oldIndex === -1 || newIndex === -1) return;
    reorderLinks(oldIndex, newIndex);
  };

  return (
    <div className="min-h-screen bg-main dark:bg-main-dark bg-main-texture flex flex-col lg:flex-row">
      <div className="w-full lg:w-1/2 bg-card dark:bg-card-dark border-r border-border dark:border-border-dark h-auto lg:h-screen overflow-y-auto flex flex-col">
        <div className="p-6 border-b border-border-subtle dark:border-border-dark flex items-center justify-between bg-card dark:bg-card-dark sticky top-0 z-10">
          <div className="flex items-center gap-4">
             {!onLogout && <button onClick={onBack} className="p-2 hover:bg-surface dark:hover:bg-surface-dark rounded-full text-text-muted dark:text-text-muted-dark"><ArrowLeft className="w-5 h-5"/></button>}
             <div>
               <h1 className="text-xl font-bold text-text-primary dark:text-text-primary-dark">Editing: {slug}</h1>
             </div>
          </div>
          <div className="flex items-center gap-2">
            {onLogout && (
              <button
                onClick={onLogout}
                className="px-4 py-2 rounded-full text-sm font-medium text-text-muted dark:text-text-muted-dark bg-card dark:bg-card-dark border border-border dark:border-border-dark hover:bg-surface dark:hover:bg-surface-dark transition-colors"
              >
                Logout
              </button>
            )}
            <button
              onClick={onSave}
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
              Save
            </button>
          </div>
        </div>

        <div className="flex-1 p-6 space-y-8">
           <div className="flex p-1 bg-surface dark:bg-surface-dark rounded-input mb-6">
              {['details', 'links', 'images', 'style', 'privacy'].map(tab => (
                <button key={tab} onClick={() => setActiveTab(tab)} className={`flex-1 py-2 text-sm font-medium rounded-button capitalize transition-all ${activeTab === tab ? 'bg-card dark:bg-surface-dark shadow text-text-primary dark:text-text-primary-dark' : 'text-text-muted dark:text-text-muted-dark hover:text-text-primary dark:hover:text-text-primary-dark'}`}>{tab}</button>
              ))}
           </div>

           {activeTab === 'details' && (
             <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Input label="First Name" value={data.personal.firstName} onChange={v => handleInputChange('personal', 'firstName', v)} />
                  <Input label="Last Name" value={data.personal.lastName} onChange={v => handleInputChange('personal', 'lastName', v)} />
                  <Input label="Job Title" value={data.personal.title} onChange={v => handleInputChange('personal', 'title', v)} />
                  <div className="space-y-1">
                    <label className="text-sm font-medium text-text-primary dark:text-text-secondary-dark">Organisation</label>
                    <div className="relative">
                      <input
                        type="text"
                        value={settings?.default_organisation || data.personal.company || ''}
                        disabled
                        className="w-full px-4 py-2.5 rounded-input border border-border dark:border-border-dark bg-surface dark:bg-surface-dark text-text-secondary dark:text-text-muted-dark cursor-not-allowed"
                        placeholder="Organisation Name"
                      />
                      <div className="absolute inset-0 flex items-center justify-end pr-3 pointer-events-none">
                        <Lock className="w-4 h-4 text-text-muted-subtle dark:text-text-muted-dark" />
                      </div>
                    </div>
                    <p className="text-xs text-text-muted dark:text-text-muted-dark mt-1">Organisation name is set by your organisation</p>
                  </div>
                </div>
                <Input label="Location" value={data.personal.location} onChange={v => handleInputChange('personal', 'location', v)} />
                <TextArea label="Bio" value={data.personal.bio} onChange={v => handleInputChange('personal', 'bio', v)} />
                <div className="h-px bg-surface dark:bg-surface-dark" />
                <div className="space-y-4">
                  <Input icon={Mail} placeholder="Email" value={data.contact.email} onChange={v => handleInputChange('contact', 'email', v)} type="email" />
                  <div className="space-y-1">
                    <PhoneInput
                      international
                      defaultCountry="GB"
                      value={data.contact.phone || ''}
                      onChange={(value) => handleInputChange('contact', 'phone', value || '')}
                      placeholder="Phone"
                      flags={flags}
                    />
                  </div>
                  <Input icon={Globe} placeholder="Website" value={data.contact.website} onChange={v => handleInputChange('contact', 'website', v)} type="url" />
                  <Input icon={Linkedin} placeholder="LinkedIn" value={data.social.linkedin} onChange={v => handleInputChange('social', 'linkedin', v)} type="url" />
                  <Input icon={Twitter} placeholder="Twitter / X" value={data.social.twitter} onChange={v => handleInputChange('social', 'twitter', v)} type="url" />
                  <Input icon={Instagram} placeholder="Instagram" value={data.social.instagram} onChange={v => handleInputChange('social', 'instagram', v)} type="url" />
                  <Input icon={Github} placeholder="Github" value={data.social.github} onChange={v => handleInputChange('social', 'github', v)} type="url" />
                </div>
             </div>
           )}

           {activeTab === 'links' && (
             <div className="space-y-6">
                <div className="flex justify-between items-center">
                    <h3 className="text-sm font-medium text-text-primary dark:text-text-secondary-dark">Custom Links</h3>
                    {settings?.allow_links_customisation !== false ? (
                      <button onClick={addLink} className="text-sm font-bold text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300 flex items-center gap-1"><Plus className="w-4 h-4" /> Add Link</button>
                    ) : (
                      <div className="flex items-center gap-2 text-text-muted dark:text-text-muted-dark">
                        <Lock className="w-4 h-4" />
                        <span className="text-sm">Locked</span>
                      </div>
                    )}
                </div>
                {settings?.allow_links_customisation === false ? (
                  <LockedOption message="Your organisation has disabled custom links. Contact your administrator to enable this feature.">
                    <div className="space-y-4">
                      {data.links.map((link, index) => (
                        <div key={link.id} className="bg-surface dark:bg-surface-dark p-4 rounded-input border border-border dark:border-border-dark">
                          <div className="grid gap-3">
                            <div className="flex gap-3 items-center">
                              <div className="w-10 h-10 rounded-container bg-card dark:bg-surface-dark border border-border dark:border-border-dark flex items-center justify-center shrink-0">
                                {React.createElement(ICON_MAP[link.icon] || LinkIcon, { className: "w-5 h-5 text-text-secondary dark:text-text-secondary-dark" })}
                              </div>
                              <input type="text" value={link.title} disabled className="flex-1 bg-card dark:bg-surface-dark border border-border dark:border-border-dark text-text-muted dark:text-text-muted-dark rounded-input px-3 py-2 text-sm cursor-not-allowed" />
                            </div>
                            <input type="text" value={link.url} disabled className="w-full bg-card dark:bg-surface-dark border border-border dark:border-border-dark text-text-muted dark:text-text-muted-dark rounded-input px-3 py-2 text-sm cursor-not-allowed" />
                          </div>
                        </div>
                      ))}
                      {data.links.length === 0 && (
                        <div className="text-center py-8 text-text-muted-subtle dark:text-text-muted-dark text-sm border-thick border-dashed border-border dark:border-border-dark rounded-input">
                          No custom links yet.
                        </div>
                      )}
                    </div>
                  </LockedOption>
                ) : (
                <div className="space-y-4">
                    <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
                      <SortableContext items={data.links.map(link => link.id)} strategy={verticalListSortingStrategy}>
                        {data.links.map((link, index) => (
                          <SortableLinkItem key={link.id} link={link}>
                            {({ setNodeRef, style, attributes, listeners }) => (
                              <div
                                ref={setNodeRef}
                                style={style}
                                className="bg-surface dark:bg-surface-dark p-4 rounded-input border border-border dark:border-border-dark relative"
                              >
                                <div className="absolute top-2 left-2 flex items-center gap-2">
                                  <button
                                    type="button"
                                    className="p-1 rounded-button border border-border dark:border-border-dark bg-card dark:bg-surface-dark text-text-muted dark:text-text-muted-dark hover:border-action-dark hover:text-action-dark dark:hover:border-action dark:hover:text-action"
                                    {...attributes}
                                    {...listeners}
                                    aria-label="Drag to reorder"
                                  >
                                    <GripVertical className="w-4 h-4" />
                                  </button>
                                </div>
                                <div className="absolute top-2 right-10 flex gap-1">
                                  <button
                                    type="button"
                                    onClick={() => moveLinkUp(index)}
                                    disabled={index === 0}
                                    className={`p-1 rounded-button border border-border dark:border-border-dark bg-card dark:bg-surface-dark text-text-muted dark:text-text-muted-dark hover:border-action-dark hover:text-action-dark dark:hover:border-action dark:hover:text-action disabled:opacity-40 disabled:cursor-not-allowed`}
                                    aria-label="Move link up"
                                  >
                                    <ChevronUp className="w-4 h-4" />
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => moveLinkDown(index)}
                                    disabled={index === data.links.length - 1}
                                    className={`p-1 rounded-button border border-border dark:border-border-dark bg-card dark:bg-surface-dark text-text-muted dark:text-text-muted-dark hover:border-action-dark hover:text-action-dark dark:hover:border-action dark:hover:text-action disabled:opacity-40 disabled:cursor-not-allowed`}
                                    aria-label="Move link down"
                                  >
                                    <ChevronDown className="w-4 h-4" />
                                  </button>
                                </div>
                                <button onClick={() => removeLink(link.id)} className="absolute top-2 right-2 text-text-muted-subtle dark:text-text-muted-dark hover:text-error-text dark:hover:text-error-text-dark hover:bg-error-bg dark:hover:bg-error-bg-dark rounded-full p-1 transition-colors" aria-label="Remove link">
                                  <X className="w-4 h-4"/>
                                </button>
                                <div className="grid gap-3 pt-6">
                                  <div className="flex gap-3 items-center">
                                    <div className="w-10 h-10 rounded-container bg-card dark:bg-surface-dark border border-border dark:border-border-dark flex items-center justify-center shrink-0">
                                      {React.createElement(ICON_MAP[link.icon], { className: "w-5 h-5 text-text-secondary dark:text-text-secondary-dark" })}
                                    </div>
                                    <input
                                      type="text"
                                      placeholder="Link Title (e.g. Download CV)"
                                      value={link.title}
                                      onChange={(e) => updateLink(link.id, 'title', e.target.value)}
                                      className="flex-1 bg-card dark:bg-surface-dark border border-border dark:border-border-dark text-text-primary dark:text-text-primary-dark rounded-input px-3 py-2 text-sm focus:outline-none focus:border-action dark:focus:border-action-dark"
                                    />
                                  </div>
                                  <input
                                    type="text"
                                    placeholder="https://..."
                                    value={link.url}
                                    onChange={(e) => updateLink(link.id, 'url', e.target.value)}
                                    className="w-full bg-card dark:bg-surface-dark border border-border dark:border-border-dark text-text-primary dark:text-text-primary-dark rounded-input px-3 py-2 text-sm focus:outline-none focus:border-action dark:focus:border-action-dark"
                                  />
                                  {/* Simple Icon Picker */}
                                  <div className="flex gap-2 overflow-x-auto pb-2 pt-1 no-scrollbar">
                                    {Object.keys(ICON_MAP).map(iconKey => (
                                      <button
                                        key={iconKey}
                                        onClick={() => updateLink(link.id, 'icon', iconKey)}
                                        className={`p-2 rounded-button border flex-shrink-0 transition-all ${link.icon === iconKey ? 'bg-indigo-50 dark:bg-indigo-900/30 border-indigo-500 dark:border-indigo-400 text-indigo-600 dark:text-indigo-300' : 'bg-card dark:bg-surface-dark border-border dark:border-border-dark text-text-muted-subtle dark:text-text-muted-dark hover:border-border dark:hover:border-border-dark'}`}
                                        title={iconKey}
                                      >
                                        {React.createElement(ICON_MAP[iconKey], { className: "w-4 h-4" })}
                                      </button>
                                    ))}
                                  </div>
                                </div>
                              </div>
                            )}
                          </SortableLinkItem>
                        ))}
                      </SortableContext>
                    </DndContext>
                    {data.links.length === 0 && (
                        <div className="text-center py-8 text-text-muted-subtle dark:text-text-muted-dark text-sm border-thick border-dashed border-border dark:border-border-dark rounded-input">
                            No custom links yet.
                        </div>
                    )}
                </div>
                )}
             </div>
           )}

           {activeTab === 'images' && (
              <div className="space-y-8">
                {settings?.allow_image_customisation === false ? (
                  <LockedOption message="Your organisation has disabled custom image uploads. Contact your administrator to enable this feature.">
                    <div className="space-y-8">
                      <ImageUpload label="Profile Picture" image={data.images.avatar} onUpload={() => {}} onRemove={() => {}} disabled={true} />
                      <ImageUpload label="Header Banner" image={data.images.banner} onUpload={() => {}} onRemove={() => {}} isBanner disabled={true} />
                    </div>
                  </LockedOption>
                ) : (
                  <>
                    {isUploading && <div className="text-center text-sm text-indigo-600 dark:text-indigo-400 animate-pulse">Uploading image...</div>}
                    <ImageUpload label="Profile Picture" image={data.images.avatar} onUpload={e => handleImageUpload('avatar', e)} onRemove={() => handleInputChange('images', 'avatar', null)} />
                    <ImageUpload label="Header Banner" image={data.images.banner} onUpload={e => handleImageUpload('banner', e)} onRemove={() => handleInputChange('images', 'banner', null)} isBanner />
                  </>
                )}
              </div>
           )}

            {activeTab === 'style' && (
               <div className="space-y-6">
                 {settings?.allow_theme_customisation === false ? (
                   <LockedOption message="Your organisation has disabled theme colour customisation. Your card will use the default theme colour.">
                     <div className="flex flex-wrap gap-4">
                       {(settings?.theme_colors || []).map(color => (
                         <div
                          key={color.name}
                          className={`w-12 h-12 rounded-full relative ${data.theme.color === color.name ? 'ring-4 ring-slate-200 scale-110' : ''}`}
                          style={{ background: color.gradientStyle || 'linear-gradient(135deg, #4f46e5, #7c3aed)' }}
                        >
                          {data.theme.color === color.name && <Check className="w-5 h-5 text-white absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-10" />}
                        </div>
                       ))}
                     </div>
                   </LockedOption>
                 ) : (
                   <div className="flex flex-wrap gap-4">
                     {(settings?.theme_colors || []).map(color => (
                       <button
                        key={color.name}
                        onClick={() => handleInputChange('theme', 'color', color.name)}
                        className={`w-12 h-12 rounded-full relative hover:scale-110 ${data.theme.color === color.name ? 'ring-4 ring-slate-200 scale-110' : ''}`}
                        style={{ background: color.gradientStyle || 'linear-gradient(135deg, #4f46e5, #7c3aed)' }}
                      >
                        {data.theme.color === color.name && <Check className="w-5 h-5 text-white absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-10" />}
                      </button>
                     ))}
                   </div>
                 )}
               </div>
            )}

            {activeTab === 'privacy' && (
              <div className="space-y-6">
                {settings?.allow_privacy_customisation === false ? (
                  <LockedOption message="Your organisation has disabled privacy settings customisation. Privacy settings are controlled by your organisation.">
                    <div className="space-y-6">
                      <Toggle
                        label="Require Interaction"
                        description="Requires users to click a button to reveal email and phone. Prevents basic bots from seeing contact info in the initial page load."
                        checked={data.privacy?.requireInteraction ?? true}
                        onChange={() => {}}
                      />
                      <div className="h-px bg-border-subtle" />
                      <Toggle
                        label="Client-Side Obfuscation"
                        description="Encodes email and phone in the HTML to make scraping harder. Note: Determined scrapers can still decode this."
                        checked={data.privacy?.clientSideObfuscation ?? false}
                        onChange={() => {}}
                      />
                      <div className="h-px bg-border-subtle" />
                      <Toggle
                        label="Block Search Engines"
                        description="Adds meta robots tag to prevent search engines from indexing this card."
                        checked={data.privacy?.blockRobots ?? false}
                        onChange={() => {}}
                      />
                    </div>
                  </LockedOption>
                ) : (
                  <div className="space-y-6">
                    <Toggle
                      label="Require Interaction"
                      description="Requires users to click a button to reveal email and phone. Prevents basic bots from seeing contact info in the initial page load."
                      checked={data.privacy?.requireInteraction ?? true}
                      onChange={(checked) => handleInputChange('privacy', 'requireInteraction', checked)}
                    />
                    <div className="h-px bg-border-subtle" />
                    <Toggle
                      label="Client-Side Obfuscation"
                      description="Encodes email and phone in the HTML to make scraping harder. Note: Determined scrapers can still decode this."
                      checked={data.privacy?.clientSideObfuscation ?? false}
                      onChange={(checked) => handleInputChange('privacy', 'clientSideObfuscation', checked)}
                    />
                    <div className="h-px bg-border-subtle" />
                    <Toggle
                      label="Block Search Engines"
                      description="Adds meta robots tag to prevent search engines from indexing this card."
                      checked={data.privacy?.blockRobots ?? false}
                      onChange={(checked) => handleInputChange('privacy', 'blockRobots', checked)}
                    />
                  </div>
                )}
              </div>
            )}
        </div>
      </div>

      <div className="hidden lg:flex w-1/2 bg-border-subtle dark:bg-card-dark items-center justify-center p-10 relative">
          <div className="w-[375px] h-[750px] bg-card dark:bg-main-dark rounded-[3rem] shadow-2xl border-device border-text-primary dark:border-border-dark overflow-hidden relative">
            <CardDisplay data={data} settings={settings} darkMode={darkMode} toggleDarkMode={toggleDarkMode} />
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

export default EditorView;
