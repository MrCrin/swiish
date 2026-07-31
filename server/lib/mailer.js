const nodemailer = require('nodemailer');
const { NODE_ENV, SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_USER, SMTP_PASSWORD, SMTP_FROM, APP_URL } = require('../config/env');

// Create email transporter (only if SMTP is configured)
let emailTransporter = null;
if (SMTP_HOST && SMTP_USER && SMTP_PASSWORD) {
  emailTransporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASSWORD
    }
  });
} else if (NODE_ENV === 'development') {
  // In development, log emails to console instead
  emailTransporter = {
    sendMail: async (options) => {
      console.log('=== EMAIL (Development Mode) ===');
      console.log('To:', options.to);
      console.log('Subject:', options.subject);
      console.log('Text:', options.text);
      console.log('HTML:', options.html);
      console.log('===============================');
      return { messageId: 'dev-' + Date.now() };
    }
  };
} else if (NODE_ENV === 'production') {
  // Warn in production if SMTP is not configured
  console.warn('WARNING: SMTP not configured. Email features (invitations, password resets) will not work.');
  console.warn('Configure SMTP_HOST, SMTP_USER, and SMTP_PASSWORD in your .env file to enable email features.');
}

// Shared by invitation-create and invitation-retry - identical template, just parameterized
async function sendInvitationEmail({ to, orgName, token }) {
  if (!emailTransporter) return;

  const invitationUrl = `${APP_URL}/invite/${token}`;
  const emailHtml = `
    <h2>You've been invited to join ${orgName}</h2>
    <p>You've been invited to join ${orgName} on Swiish. Click the link below to accept the invitation and create your account.</p>
    <p><a href="${invitationUrl}" style="background-color: #4f46e5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Accept Invitation</a></p>
    <p>This invitation will expire in 7 days.</p>
    <p>If you didn't expect this invitation, you can safely ignore this email.</p>
  `;
  const emailText = `You've been invited to join ${orgName} on Swiish. Visit ${invitationUrl} to accept the invitation. This invitation expires in 7 days.`;

  await emailTransporter.sendMail({
    from: SMTP_FROM,
    to,
    subject: `Invitation to join ${orgName} on Swiish`,
    text: emailText,
    html: emailHtml
  });
}

async function sendPasswordResetEmail({ to, token }) {
  if (!emailTransporter) return;

  const resetUrl = `${APP_URL}/reset-password/${token}`;
  const emailHtml = `
    <h2>Password Reset Request</h2>
    <p>You requested to reset your password for your Swiish account. Click the link below to reset your password:</p>
    <p><a href="${resetUrl}" style="background-color: #4f46e5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a></p>
    <p>This link will expire in 1 hour.</p>
    <p>If you didn't request a password reset, you can safely ignore this email.</p>
  `;
  const emailText = `You requested to reset your password. Visit ${resetUrl} to reset it. This link expires in 1 hour.`;

  await emailTransporter.sendMail({
    from: SMTP_FROM,
    to,
    subject: 'Reset your Swiish password',
    text: emailText,
    html: emailHtml
  });
}

async function sendVerificationEmail({ to, token }) {
  if (!emailTransporter) return;

  const verifyUrl = `${APP_URL}/verify-email/${token}`;
  const emailHtml = `
    <h2>Verify Your Email Address</h2>
    <p>Please verify your email address by clicking the link below:</p>
    <p><a href="${verifyUrl}" style="background-color: #4f46e5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Email</a></p>
    <p>This link will expire in 7 days.</p>
    <p>If you didn't create an account, you can safely ignore this email.</p>
  `;
  const emailText = `Please verify your email address by visiting ${verifyUrl}. This link expires in 7 days.`;

  await emailTransporter.sendMail({
    from: SMTP_FROM,
    to,
    subject: 'Verify your Swiish email address',
    text: emailText,
    html: emailHtml
  });
}

module.exports = {
  emailTransporter,
  sendInvitationEmail,
  sendPasswordResetEmail,
  sendVerificationEmail,
};
