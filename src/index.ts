import { Hono } from 'hono';
import dns from 'node:dns/promises';
import tls from 'node:tls';
import net from 'node:net';
import crypto from 'node:crypto';
import https from 'node:https';
import { AsyncLocalStorage } from 'node:async_hooks';

// Types
interface TelegramUpdate {
  message?: {
    chat: { id: number };
    text?: string;
    message_id: number;
    from?: { id: number; first_name: string };
  };
  callback_query?: {
    id: string;
    message: {
      chat: { id: number };
      message_id: number;
    };
    data: string;
    from: { id: number };
  };
}

interface Env {
  BOT_TOKEN: string;
  KV_STORAGE: KVNamespace;
  AI: any;
}

// Telegram Bot Helper
class TelegramBot {
  constructor(private token: string) {}

  async sendMessage(chatId: number, text: string, options: any = {}) {
    const response = await fetch(`https://api.telegram.org/bot${this.token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
        ...options,
      }),
    });
    return response.json();
  }

  async editMessage(chatId: number, messageId: number, text: string, options: any = {}) {
    await fetch(`https://api.telegram.org/bot${this.token}/editMessageText`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        message_id: messageId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
        ...options,
      }),
    });
  }

  async answerCallback(callbackId: string, text: string) {
    await fetch(`https://api.telegram.org/bot${this.token}/answerCallbackQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ callback_query_id: callbackId, text }),
    });
  }

  async sendDocument(chatId: number, content: string, filename: string, caption?: string) {
    const blob = new Blob([content], { type: 'text/plain' });
    const formData = new FormData();
    formData.append('chat_id', chatId.toString());
    formData.append('document', blob, filename);
    if (caption) formData.append('caption', caption);

    await fetch(`https://api.telegram.org/bot${this.token}/sendDocument`, {
      method: 'POST',
      body: formData,
    });
  }
}

// DNS Analyzer
class DNSAnalyzer {
  static async analyze(domain: string, kv?: KVNamespace): Promise<string> {
    try {
      const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
      
      if (kv) {
        const cached = await kv.get(`dns:${cleanDomain}`);
        if (cached) return cached + '\n\n<i>🔄 Cached (1h TTL)</i>';
      }

      let result = `🔍 <b>DNS Analysis: ${cleanDomain}</b>\n⏰ ${new Date().toISOString()}\n\n`;

      // A Records
      try {
        const aRecords = await dns.resolve4(cleanDomain);
        result += `📍 <b>A Records (IPv4):</b>\n`;
        aRecords.slice(0, 5).forEach(ip => result += `  • ${ip}\n`);
        result += '\n';
      } catch { result += `📍 <b>A Records:</b> Not found\n\n`; }

      // AAAA Records
      try {
        const aaaaRecords = await dns.resolve6(cleanDomain);
        result += `📍 <b>AAAA Records (IPv6):</b>\n`;
        aaaaRecords.slice(0, 3).forEach(ip => result += `  • ${ip}\n`);
        result += '\n';
      } catch { result += `📍 <b>AAAA Records:</b> Not found\n\n`; }

      // MX Records
      try {
        const mxRecords = await dns.resolveMx(cleanDomain);
        result += `📧 <b>MX Records:</b>\n`;
        mxRecords.sort((a, b) => a.priority - b.priority).slice(0, 5)
          .forEach(mx => result += `  • [${mx.priority}] ${mx.exchange}\n`);
        result += '\n';
      } catch { result += `📧 <b>MX Records:</b> Not found\n\n`; }

      // TXT Records
      try {
        const txtRecords = await dns.resolveTxt(cleanDomain);
        result += `📝 <b>TXT Records:</b>\n`;
        txtRecords.slice(0, 5).forEach(txt => {
          const record = txt.join('');
          result += `  • ${record.substring(0, 100)}${record.length > 100 ? '...' : ''}\n`;
        });
        result += '\n';
      } catch { result += `📝 <b>TXT Records:</b> Not found\n\n`; }

      // NS Records
      try {
        const nsRecords = await dns.resolveNs(cleanDomain);
        result += `🌐 <b>Nameservers:</b>\n`;
        nsRecords.slice(0, 5).forEach(ns => result += `  • ${ns}\n`);
        result += '\n';
      } catch { result += `🌐 <b>Nameservers:</b> Not found\n\n`; }

      // SOA Record
      try {
        const soaRecord = await dns.resolveSoa(cleanDomain);
        result += `📋 <b>SOA Record:</b>\n`;
        result += `  • Primary NS: ${soaRecord.nsname}\n`;
        result += `  • Serial: ${soaRecord.serial}\n\n`;
      } catch {}

      // CNAME
      try {
        const cname = await dns.resolveCname(cleanDomain);
        result += `🔗 <b>CNAME:</b>\n`;
        cname.forEach(c => result += `  • ${c}\n`);
        result += '\n';
      } catch {}

      // CAA Records
      try {
        const caaRecords = await dns.resolveCaa(cleanDomain);
        if (caaRecords.length > 0) {
          result += `🔒 <b>CAA Records:</b>\n`;
          caaRecords.forEach(caa => result += `  • ${caa.issue || caa.issuewild || caa.iodef}\n`);
          result += '\n';
        }
      } catch {}

      if (kv) await kv.put(`dns:${cleanDomain}`, result, { expirationTtl: 3600 });
      return result;
    } catch (error: any) {
      return `❌ <b>DNS Failed</b>\n\n${error.message}`;
    }
  }

  static async reverseLookup(ip: string): Promise<string> {
    try {
      const hostnames = await dns.reverse(ip);
      let result = `🔄 <b>Reverse DNS: ${ip}</b>\n\n<b>Hostnames:</b>\n`;
      hostnames.forEach(host => result += `  • ${host}\n`);
      return result;
    } catch (error: any) {
      return `❌ <b>Reverse Lookup Failed</b>\n\n${error.message}`;
    }
  }
}

// SSL Inspector
class SSLInspector {
  static async inspect(domain: string): Promise<string> {
    return new Promise((resolve) => {
      try {
        const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        const host = cleanDomain.split(':')[0];
        const port = parseInt(cleanDomain.split(':')[1] || '443');

        const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
          const cert = socket.getPeerCertificate(true);
          const cipher = socket.getCipher();
          const protocol = socket.getProtocol();

          let result = `🔒 <b>SSL Certificate: ${host}</b>\n⏰ ${new Date().toISOString()}\n\n`;

          result += `📜 <b>Certificate:</b>\n`;
          result += `  • Subject: ${cert.subject?.CN || 'N/A'}\n`;
          result += `  • Issuer: ${cert.issuer?.O || cert.issuer?.CN || 'N/A'}\n`;
          result += `  • Valid: ${new Date(cert.valid_from).toLocaleDateString()} - ${new Date(cert.valid_to).toLocaleDateString()}\n`;

          const daysLeft = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
          result += `  • Expires in: ${daysLeft} days`;
          if (daysLeft < 7) result += ` 🚨`;
          else if (daysLeft < 30) result += ` ⚠️`;
          else result += ` ✅`;
          result += '\n\n';

          result += `🔐 <b>Fingerprints:</b>\n`;
          result += `  • SHA256: ${cert.fingerprint256?.substring(0, 40)}...\n\n`;

          if (cert.subjectaltname) {
            const sans = cert.subjectaltname.split(', ').slice(0, 8);
            result += `🏷 <b>Alt Names (${sans.length}):</b>\n`;
            sans.forEach(san => result += `  • ${san.replace('DNS:', '')}\n`);
            result += '\n';
          }

          result += `🔐 <b>Connection:</b>\n`;
          result += `  • Protocol: ${protocol || 'Unknown'}\n`;
          result += `  • Cipher: ${cipher?.name || 'Unknown'}\n\n`;

          result += `✅ <b>Security:</b>\n`;
          let score = 0;
          if (protocol?.includes('TLSv1.3')) { score += 40; result += `  • ✅ TLS 1.3\n`; }
          else if (protocol?.includes('TLSv1.2')) { score += 30; result += `  • 🟡 TLS 1.2\n`; }
          else { result += `  • ❌ Outdated Protocol\n`; }

          if (cipher?.name?.includes('AES') && cipher?.name?.includes('GCM')) {
            score += 30; result += `  • ✅ Strong Cipher\n`;
          }
          if (cipher?.name?.includes('ECDHE')) { score += 15; result += `  • ✅ Forward Secrecy\n`; }
          if (daysLeft > 30) { score += 15; result += `  • ✅ Valid Cert\n`; }

          result += `\n📊 <b>Score: ${score}/100</b> - `;
          if (score >= 85) result += `🟢 Excellent`;
          else if (score >= 70) result += `🟡 Good`;
          else result += `🔴 Poor`;

          socket.end();
          resolve(result);
        });

        socket.on('error', (error: any) => resolve(`❌ <b>SSL Failed</b>\n\n${error.message}`));
        socket.setTimeout(15000, () => { socket.destroy(); resolve(`❌ Timeout`); });
      } catch (error: any) {
        resolve(`❌ <b>SSL Failed</b>\n\n${error.message}`);
      }
    });
  }
}

// Email Security Validator
class EmailSecurityValidator {
  static async validate(domain: string): Promise<string> {
    try {
      const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').split('@').pop() || domain;
      let result = `📧 <b>Email Security: ${cleanDomain}</b>\n⏰ ${new Date().toISOString()}\n\n`;
      let score = 0, maxScore = 0;

      // SPF
      maxScore += 25;
      try {
        const txtRecords = await dns.resolveTxt(cleanDomain);
        const spf = txtRecords.find(r => r.join('').startsWith('v=spf1'));
        if (spf) {
          const spfStr = spf.join('');
          result += `✅ <b>SPF Found:</b>\n  ${spfStr.substring(0, 120)}...\n`;
          if (spfStr.includes('-all')) { score += 25; result += `  • 🟢 Hard Fail\n`; }
          else if (spfStr.includes('~all')) { score += 20; result += `  • 🟡 Soft Fail\n`; }
          else { score += 10; result += `  • 🟠 Weak\n`; }
          result += '\n';
        } else {
          result += `❌ <b>SPF:</b> Not found\n\n`;
        }
      } catch { result += `❌ <b>SPF:</b> Error\n\n`; }

      // DMARC
      maxScore += 30;
      try {
        const dmarcRecords = await dns.resolveTxt(`_dmarc.${cleanDomain}`);
        const dmarc = dmarcRecords.find(r => r.join('').startsWith('v=DMARC1'));
        if (dmarc) {
          const dmarcStr = dmarc.join('');
          result += `✅ <b>DMARC Found:</b>\n  ${dmarcStr.substring(0, 120)}...\n`;
          if (dmarcStr.includes('p=reject')) { score += 30; result += `  • 🟢 Reject\n`; }
          else if (dmarcStr.includes('p=quarantine')) { score += 25; result += `  • 🟡 Quarantine\n`; }
          else { score += 15; result += `  • 🟠 None\n`; }
          result += '\n';
        } else {
          result += `❌ <b>DMARC:</b> Not found\n\n`;
        }
      } catch { result += `❌ <b>DMARC:</b> Not found\n\n`; }

      // DKIM
      maxScore += 15;
      result += `🔑 <b>DKIM Check:</b>\n`;
      const selectors = ['default', 'google', 'k1', 'selector1'];
      let dkimFound = false;
      for (const sel of selectors) {
        try {
          const dkim = await dns.resolveTxt(`${sel}._domainkey.${cleanDomain}`);
          if (dkim.length > 0) {
            result += `  • ✅ ${sel}._domainkey\n`;
            dkimFound = true;
            score += 15;
            break;
          }
        } catch {}
      }
      if (!dkimFound) result += `  • ❌ Not found\n`;
      result += '\n';

      // MX
      maxScore += 20;
      try {
        const mxRecords = await dns.resolveMx(cleanDomain);
        result += `📬 <b>MX (${mxRecords.length}):</b>\n`;
        if (mxRecords.length > 0) {
          score += 20;
          mxRecords.sort((a, b) => a.priority - b.priority).slice(0, 3)
            .forEach(mx => result += `  • [${mx.priority}] ${mx.exchange}\n`);
        }
        result += '\n';
      } catch { result += `❌ <b>MX:</b> Not found\n\n`; }

      const pct = Math.round((score / maxScore) * 100);
      result += `📊 <b>Score: ${pct}/100</b> - `;
      if (pct >= 90) result += `A+ 🟢`;
      else if (pct >= 80) result += `A 🟢`;
      else if (pct >= 70) result += `B 🟡`;
      else if (pct >= 60) result += `C 🟠`;
      else result += `F 🔴`;

      return result;
    } catch (error: any) {
      return `❌ <b>Email Check Failed</b>\n\n${error.message}`;
    }
  }
}

// Website Health Monitor
class WebsiteHealthMonitor {
  static async check(url: string): Promise<string> {
    try {
      const start = Date.now();
      if (!url.startsWith('http')) url = 'https://' + url;

      const response = await fetch(url, { method: 'HEAD', redirect: 'follow' });
      const loadTime = Date.now() - start;
      const urlObj = new URL(url);

      let result = `🏥 <b>Health Check: ${urlObj.hostname}</b>\n⏰ ${new Date().toISOString()}\n\n`;

      result += `📊 <b>Status:</b> `;
      if (response.status >= 200 && response.status < 300) result += `✅ ${response.status} ${response.statusText}\n\n`;
      else if (response.status >= 300 && response.status < 400) result += `🔄 ${response.status}\n\n`;
      else result += `❌ ${response.status}\n\n`;

      result += `⚡ <b>Performance:</b>\n  • Response: ${loadTime}ms `;
      if (loadTime < 200) result += `🟢\n`;
      else if (loadTime < 500) result += `🟡\n`;
      else result += `🔴\n`;
      result += '\n';

      const server = response.headers.get('server');
      if (server) result += `🖥 <b>Server:</b> ${server}\n\n`;

      result += `🔒 <b>Security Headers:</b>\n`;
      const headers = [
        { name: 'strict-transport-security', label: 'HSTS' },
        { name: 'x-frame-options', label: 'X-Frame-Options' },
        { name: 'x-content-type-options', label: 'X-Content-Type' },
        { name: 'content-security-policy', label: 'CSP' },
      ];

      let headerScore = 0;
      headers.forEach(h => {
        if (response.headers.get(h.name)) {
          result += `  • ✅ ${h.label}\n`;
          headerScore++;
        } else {
          result += `  • ❌ ${h.label}\n`;
        }
      });

      const perfScore = loadTime < 300 ? 30 : 15;
      const statusScore = response.status < 300 ? 30 : 0;
      const secScore = (headerScore / headers.length) * 40;
      const total = Math.round(perfScore + statusScore + secScore);

      result += `\n📈 <b>Score: ${total}/100</b> - `;
      if (total >= 85) result += `🟢 Excellent`;
      else if (total >= 70) result += `🟡 Good`;
      else if (total >= 50) result += `🟠 Fair`;
      else result += `🔴 Poor`;

      return result;
    } catch (error: any) {
      return `❌ <b>Health Check Failed</b>\n\n${error.message}`;
    }
  }
}

// Hash Generator using crypto
class HashGenerator {
  static generate(text: string): string {
    const algorithms = ['md5', 'sha1', 'sha256', 'sha512'];
    let result = `🔐 <b>Hash Generator</b>\n\nInput: ${text.substring(0, 50)}...\n\n`;
    
    algorithms.forEach(algo => {
      const hash = crypto.createHash(algo).update(text).digest('hex');
      result += `<b>${algo.toUpperCase()}:</b>\n<code>${hash}</code>\n\n`;
    });

    return result;
  }
}

// Port Scanner
class PortScanner {
  static async scan(host: string, ports: number[]): Promise<string> {
    let result = `🔍 <b>Port Scan: ${host}</b>\n⏰ ${new Date().toISOString()}\n\n`;
    
    for (const port of ports.slice(0, 10)) {
      try {
        await new Promise<void>((resolve, reject) => {
          const socket = net.createConnection({ host, port, timeout: 3000 }, () => {
            socket.end();
            resolve();
          });
          socket.on('error', reject);
          socket.on('timeout', () => { socket.destroy(); reject(); });
        });
        result += `  • Port ${port}: ✅ Open\n`;
      } catch {
        result += `  • Port ${port}: ❌ Closed\n`;
      }
    }

    return result;
  }
}

// AI-Powered Security Analyzer using Cloudflare AI
class AISecurityAnalyzer {
  static async analyze(data: string, ai: any): Promise<string> {
    try {
      const response = await ai.run('@cf/meta/llama-3-8b-instruct', {
        prompt: `Analyze this security data and provide recommendations:\n\n${data}\n\nProvide: 1) Security score, 2) Vulnerabilities, 3) Recommendations`,
        max_tokens: 500,
      });

      return `🤖 <b>AI Security Analysis</b>\n\n${response.response}`;
    } catch (error: any) {
      return `❌ AI analysis unavailable: ${error.message}`;
    }
  }
}

// Main App
const app = new Hono<{ Bindings: Env }>();

app.post('/webhook', async (c) => {
  const update: TelegramUpdate = await c.req.json();
  const bot = new TelegramBot(c.env.BOT_TOKEN);
  const kv = c.env.KV_STORAGE;
  const ai = c.env.AI;

  if (update.callback_query) {
    const { id, data, message } = update.callback_query;
    await bot.answerCallback(id, 'Processing...');
    await bot.sendMessage(message.chat.id, `Send domain/URL for <b>${data}</b> check`);
    return c.json({ ok: true });
  }

  if (update.message?.text) {
    const chatId = update.message.chat.id;
    const text = update.message.text;

    if (text === '/start') {
      const msg = `🤖 <b>Advanced Network Tools Bot</b>

<b>🔧 Available Tools:</b>

🔍 /dns &lt;domain&gt; - Complete DNS Analysis
🔒 /ssl &lt;domain&gt; - SSL/TLS Certificate Inspector
📧 /email &lt;domain&gt; - Email Security Validator
🏥 /health &lt;url&gt; - Website Health Monitor
🔄 /reverse &lt;ip&gt; - Reverse DNS Lookup
🔐 /hash &lt;text&gt; - Hash Generator (MD5/SHA)
🔍 /port &lt;host&gt; &lt;ports&gt; - Port Scanner
🤖 /ai &lt;domain&gt; - AI Security Analysis
📊 /report &lt;domain&gt; - Full Report (PDF)
💾 /history - Your scan history

<b>Examples:</b>
/dns google.com
/ssl github.com
/email cloudflare.com
/health https://example.com
/reverse 8.8.8.8
/hash hello world
/port example.com 80,443,8080
/ai cloudflare.com

Powered by Cloudflare Workers + AI ⚡`;

      await bot.sendMessage(chatId, msg, {
        reply_markup: {
          inline_keyboard: [
            [{ text: '🔍 DNS', callback_data: 'dns' }, { text: '🔒 SSL', callback_data: 'ssl' }],
            [{ text: '📧 Email', callback_data: 'email' }, { text: '🏥 Health', callback_data: 'health' }],
            [{ text: '🤖 AI Analysis', callback_data: 'ai' }, { text: '📊 Full Report', callback_data: 'report' }],
          ]
        }
      });
    } else if (text.startsWith('/dns ')) {
      const domain = text.replace('/dns ', '').trim();
      const loading = await bot.sendMessage(chatId, '🔍 Analyzing DNS...');
      const result = await DNSAnalyzer.analyze(domain, kv);
      await bot.editMessage(chatId, loading.result.message_id, result);
      
      // Save to history
      if (kv) await kv.put(`history:${chatId}:${Date.now()}`, `DNS:${domain}`, { expirationTtl: 604800 });
    } else if (text.startsWith('/ssl ')) {
      const domain = text.replace('/ssl ', '').trim();
      const loading = await bot.sendMessage(chatId, '🔒 Inspecting SSL...');
      const result = await SSLInspector.inspect(domain);
      await bot.editMessage(chatId, loading.result.message_id, result);
    } else if (text.startsWith('/email ')) {
      const domain = text.replace('/email ', '').trim();
      const loading = await bot.sendMessage(chatId, '📧 Checking email security...');
      const result = await EmailSecurityValidator.validate(domain);
      await bot.editMessage(chatId, loading.result.message_id, result);
    } else if (text.startsWith('/health ')) {
      const url = text.replace('/health ', '').trim();
      const loading = await bot.sendMessage(chatId, '🏥 Checking website health...');
      const result = await WebsiteHealthMonitor.check(url);
      await bot.editMessage(chatId, loading.result.message_id, result);
    } else if (text.startsWith('/reverse ')) {
      const ip = text.replace('/reverse ', '').trim();
      const loading = await bot.sendMessage(chatId, '🔄 Reverse lookup...');
      const result = await DNSAnalyzer.reverseLookup(ip);
      await bot.editMessage(chatId, loading.result.message_id, result);
    } else if (text.startsWith('/hash ')) {
      const input = text.replace('/hash ', '').trim();
      const result = HashGenerator.generate(input);
      await bot.sendMessage(chatId, result);
    } else if (text.startsWith('/port ')) {
      const parts = text.replace('/port ', '').trim().split(' ');
      const host = parts[0];
      const ports = parts[1]?.split(',').map(p => parseInt(p)) || [80, 443, 8080, 3000];
      const loading = await bot.sendMessage(chatId, '🔍 Scanning ports...');
      const result = await PortScanner.scan(host, ports);
      await bot.editMessage(chatId, loading.result.message_id, result);
    } else if (text.startsWith('/ai ')) {
      if (!ai) {
        await bot.sendMessage(chatId, '❌ AI service not configured');
        return c.json({ ok: true });
      }
      const domain = text.replace('/ai ', '').trim();
      const loading = await bot.sendMessage(chatId, '🤖 AI analyzing...');
      
      // Gather data
      const dnsData = await DNSAnalyzer.analyze(domain, kv);
      const sslData = await SSLInspector.inspect(domain);
      const emailData = await EmailSecurityValidator.validate(domain);
      
      const combined = `${dnsData}\n\n${sslData}\n\n${emailData}`;
      const aiResult = await AISecurityAnalyzer.analyze(combined, ai);
      
      await bot.editMessage(chatId, loading.result.message_id, aiResult);
    } else if (text.startsWith('/report ')) {
      const domain = text.replace('/report ', '').trim();
      await bot.sendMessage(chatId, '📊 Generating comprehensive report...');
      
      // Gather all data
      const dnsData = await DNSAnalyzer.analyze(domain, kv);
      const sslData = await SSLInspector.inspect(domain);
      const emailData = await EmailSecurityValidator.validate(domain);
      const healthData = await WebsiteHealthMonitor.check(`https://${domain}`);
      
      const report = `COMPREHENSIVE SECURITY REPORT
Generated: ${new Date().toISOString()}
Domain: ${domain}

${dnsData}

${sslData}

${emailData}

${healthData}

---
Report generated by Network Tools Bot
Powered by Cloudflare Workers`;

      await bot.sendDocument(chatId, report, `${domain}_report.txt`, `📊 Full security report for ${domain}`);
    } else if (text === '/history') {
      if (!kv) {
        await bot.sendMessage(chatId, '💾 History not available');
        return c.json({ ok: true });
      }
      
      const list = await kv.list({ prefix: `history:${chatId}:` });
      if (list.keys.length === 0) {
        await bot.sendMessage(chatId, '📝 No scan history found');
      } else {
        let history = `📜 <b>Your Scan History</b>\n\n`;
        for (const key of list.keys.slice(0, 10)) {
          const value = await kv.get(key.name);
          const timestamp = new Date(parseInt(key.name.split(':')[2]));
          history += `• ${timestamp.toLocaleString()}: ${value}\n`;
        }
        await bot.sendMessage(chatId, history);
      }
    } else {
      await bot.sendMessage(chatId, '❓ Unknown command. Use /start to see available commands.');
    }
  }

  return c.json({ ok: true });
});

app.get('/', (c) => c.text('🤖 Network Tools Bot is running!'));

export default app;
