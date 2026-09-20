import { Resend } from 'resend';

let resend: Resend | null = null;

function getResend() {
  const key = process.env.RESEND_API_KEY?.trim();
  if (!key) return null;
  resend ??= new Resend(key);
  return resend;
}

export function getEmailFrom() {
  return process.env.EMAIL_FROM?.trim() || process.env.RESET_FROM_EMAIL?.trim() || 'Business Quotes <no-reply@invalid.example>';
}

export function isEmailConfigured() {
  return Boolean(process.env.RESEND_API_KEY?.trim() && getEmailFrom().includes('@'));
}

export async function sendEmail(options: {
  to: string;
  subject: string;
  html: string;
  replyTo?: string | null;
}) {
  const client = getResend();
  if (!client) throw new Error('Email service is not configured. Add RESEND_API_KEY and EMAIL_FROM in Railway.');

  const safeSubject = options.subject.replace(/[\r\n]+/g, ' ').trim().slice(0, 200);
  if (!safeSubject) throw new Error('Email subject is required');
  const result = await client.emails.send({
    from: getEmailFrom(),
    to: options.to,
    subject: safeSubject,
    html: options.html,
    ...(options.replyTo ? { replyTo: options.replyTo } : {}),
  });

  if (result.error) throw new Error(result.error.message || 'Email provider error');
  return result.data;
}
