import tls from 'node:tls';
import type { TLSSocket } from 'node:tls';

let smtpPromise: Promise<void> | null = null;

function getProvider() {
  return (process.env.EMAIL_PROVIDER?.trim().toLowerCase() || 'gmail');
}

function getSmtpHost() {
  return process.env.SMTP_HOST?.trim() || (getProvider() === 'gmail' ? 'smtp.gmail.com' : '');
}

function getSmtpPort() {
  const configured = Number(process.env.SMTP_PORT ?? (getProvider() === 'gmail' ? 465 : 587));
  return Number.isFinite(configured) && configured > 0 ? configured : 465;
}

function getSmtpSecure() {
  if (process.env.SMTP_SECURE != null) return process.env.SMTP_SECURE.trim().toLowerCase() === 'true';
  return getSmtpPort() === 465;
}

function getSmtpUser() {
  return process.env.SMTP_USER?.trim() || '';
}

function getSmtpPassword() {
  return process.env.SMTP_PASSWORD?.replace(/\s+/g, '').trim() || '';
}

function getSmtpFrom() {
  return process.env.EMAIL_FROM?.trim() || process.env.RESET_FROM_EMAIL?.trim() || getSmtpUser();
}

function assertSafeHeader(value: string, field: string) {
  if (/[\r\n]/.test(value)) throw new Error(`Invalid ${field}`);
}

function encodeBase64(value: string) {
  return Buffer.from(value, 'utf8').toString('base64');
}

function htmlToTextFallback(html: string) {
  return html
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .trim();
}

class SmtpClient {
  private socket: TLSSocket;
  private buffer = '';
  private waiters: Array<{ resolve: (value: string) => void; reject: (error: Error) => void }> = [];
  private closed = false;

  constructor(socket: TLSSocket) {
    this.socket = socket;
    socket.setTimeout(20_000);
    socket.on('data', (chunk) => {
      this.buffer += chunk.toString('utf8');
      this.flushResponses();
    });
    socket.on('error', (error) => this.fail(error instanceof Error ? error : new Error(String(error))));
    socket.on('timeout', () => this.fail(new Error('SMTP connection timed out')));
    socket.on('close', () => {
      if (!this.closed) this.fail(new Error('SMTP connection closed unexpectedly'));
    });
  }

  private fail(error: Error) {
    this.closed = true;
    for (const waiter of this.waiters.splice(0)) waiter.reject(error);
  }

  private extractResponse(): string | null {
    const firstBreak = this.buffer.indexOf('\r\n');
    if (firstBreak < 0) return null;
    const firstLine = this.buffer.slice(0, firstBreak);
    const match = firstLine.match(/^(\d{3})([ -])/);
    if (!match) return null;
    const code = match[1];
    let end = firstBreak + 2;
    if (match[2] === '-') {
      const finalMarker = `\r\n${code} `;
      const finalIndex = this.buffer.indexOf(finalMarker, end);
      if (finalIndex < 0) return null;
      const finalBreak = this.buffer.indexOf('\r\n', finalIndex + finalMarker.length);
      if (finalBreak < 0) return null;
      end = finalBreak + 2;
    }
    const response = this.buffer.slice(0, end);
    this.buffer = this.buffer.slice(end);
    return response;
  }

  private flushResponses() {
    while (this.waiters.length) {
      const response = this.extractResponse();
      if (!response) return;
      this.waiters.shift()!.resolve(response);
    }
  }

  async readResponse() {
    const response = this.extractResponse();
    if (response) return response;
    return await new Promise<string>((resolve, reject) => {
      this.waiters.push({ resolve, reject });
      this.flushResponses();
    });
  }

  async command(command: string, expected: number[]) {
    this.socket.write(`${command}\r\n`);
    const response = await this.readResponse();
    const code = Number(response.slice(0, 3));
    if (!expected.includes(code)) throw new Error(`SMTP ${code}: ${response.trim().slice(0, 500)}`);
    return response;
  }

  async data(message: string) {
    const normalized = message.replace(/\r?\n/g, '\r\n').replace(/(^|\r\n)\./g, '$1..');
    this.socket.write(`${normalized}\r\n.\r\n`);
    const response = await this.readResponse();
    const code = Number(response.slice(0, 3));
    if (code !== 250) throw new Error(`SMTP ${code}: ${response.trim().slice(0, 500)}`);
  }

  close() {
    this.closed = true;
    try { this.socket.end(); } catch {}
  }
}

async function createSmtpClient() {
  const host = getSmtpHost();
  const port = getSmtpPort();
  if (!host) throw new Error('SMTP_HOST is not configured.');
  if (!getSmtpSecure()) throw new Error('This Gmail SMTP integration uses implicit TLS. Set SMTP_SECURE=true and SMTP_PORT=465.');

  const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: true });
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => { cleanup(); reject(error); };
    const onSecure = () => { cleanup(); resolve(); };
    const cleanup = () => {
      socket.off('error', onError);
      socket.off('secureConnect', onSecure);
    };
    socket.once('error', onError);
    socket.once('secureConnect', onSecure);
  });

  const client = new SmtpClient(socket);
  await client.readResponse().then((response) => {
    if (Number(response.slice(0, 3)) !== 220) throw new Error(`SMTP greeting failed: ${response.trim().slice(0, 500)}`);
  });
  await client.command(`EHLO ${process.env.SMTP_EHLO_DOMAIN?.trim() || 'business-quotes.local'}`, [250]);
  return client;
}

async function sendSmtpEmail(options: { to: string; subject: string; html: string; replyTo?: string | null }) {
  const user = getSmtpUser();
  const password = getSmtpPassword();
  const from = getSmtpFrom();
  if (!user || !password || !from) throw new Error('Email service is not configured. Add SMTP_USER, SMTP_PASSWORD and EMAIL_FROM in Railway.');

  for (const [value, field] of [[options.to, 'recipient'], [from, 'sender']] as const) assertSafeHeader(value, field);
  if (options.replyTo) assertSafeHeader(options.replyTo, 'reply-to');

  const client = await createSmtpClient();
  try {
    await client.command('AUTH LOGIN', [334]);
    await client.command(encodeBase64(user), [334]);
    await client.command(encodeBase64(password), [235]);
    await client.command(`MAIL FROM:<${user}>`, [250]);
    await client.command(`RCPT TO:<${options.to}>`, [250, 251]);
    await client.command('DATA', [354]);

    const safeSubject = options.subject.replace(/[\r\n]+/g, ' ').trim().slice(0, 200);
    if (!safeSubject) throw new Error('Email subject is required');
    const text = htmlToTextFallback(options.html);
    const boundary = `=_BusinessQuotes_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const message = [
      `From: ${from}`,
      `To: ${options.to}`,
      `Subject: ${safeSubject}`,
      'MIME-Version: 1.0',
      `Content-Type: multipart/alternative; boundary="${boundary}"`,
      ...(options.replyTo ? [`Reply-To: ${options.replyTo}`] : []),
      '',
      `--${boundary}`,
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: 8bit',
      '',
      text,
      '',
      `--${boundary}`,
      'Content-Type: text/html; charset=UTF-8',
      'Content-Transfer-Encoding: 8bit',
      '',
      options.html,
      '',
      `--${boundary}--`,
    ].join('\r\n');

    await client.data(message);
    await client.command('QUIT', [221, 250]).catch(() => {});
    return { messageId: null };
  } finally {
    client.close();
  }
}

export function getEmailFrom() {
  return getSmtpFrom() || 'Business Quotes <no-reply@invalid.example>';
}

export function getEmailProvider() {
  return getProvider();
}

export function isEmailConfigured() {
  return Boolean(getSmtpHost() && getSmtpUser() && getSmtpPassword() && getEmailFrom().includes('@'));
}

export async function sendEmail(options: {
  to: string;
  subject: string;
  html: string;
  replyTo?: string | null;
}) {
  if (!isEmailConfigured()) {
    throw new Error('Email service is not configured. Add SMTP_USER, SMTP_PASSWORD and EMAIL_FROM in Railway.');
  }
  // Serialize SMTP connections so a single Railway process does not interleave
  // authentication or message commands across sockets.
  const current = smtpPromise ?? Promise.resolve();
  const next = current.catch(() => {}).then(() => sendSmtpEmail(options));
  smtpPromise = next.then(() => undefined, () => undefined);
  return next;
}
