// --- DATA TEMPLATE ---
const getDefaultTemplate = (settings) => ({
  personal: {
    firstName: "New",
    lastName: "User",
    title: "Role Title",
    company: settings?.default_organisation || "My Organisation",
    bio: "Welcome to the team.",
    location: "London, UK"
  },
  contact: {
    email: "",
    phone: "",
    website: "",
  },
  social: { linkedin: "", twitter: "", instagram: "", github: "" },
  theme: { color: "indigo", style: "modern" },
  images: { avatar: null, banner: null },
  links: [],
  privacy: {
    requireInteraction: true,  // ON by default
    clientSideObfuscation: false,  // OFF by default
    blockRobots: false  // OFF by default
  }
});

export { getDefaultTemplate };
