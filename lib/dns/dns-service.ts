import { Resolver } from 'dns/promises';
import crypto from 'crypto';
import { DnsCheckStatus } from '@/lib/db/db';

export function generateDkimKeys(): { selector: string; publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  // Extract clean public key base64 for DNS TXT record
  const cleanPublicKey = publicKey
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\s+/g, '');

  return {
    selector: 'mail',
    publicKey: cleanPublicKey,
    privateKey
  };
}

export interface DnsVerifyExpectedConfig {
  expectedIp?: string;
  expectedMx?: string;
  dkimSelector?: string;
  dkimPublicKey?: string;
}

export async function verifyDomainDns(
  domain: string,
  config?: string | DnsVerifyExpectedConfig
): Promise<DnsCheckStatus> {
  const expected: DnsVerifyExpectedConfig =
    typeof config === 'string' ? { expectedIp: config } : (config || {});

  const expectedIp = expected.expectedIp && expected.expectedIp !== '0.0.0.0' && expected.expectedIp !== '127.0.0.1'
    ? expected.expectedIp.trim()
    : undefined;
  const expectedMx = (expected.expectedMx || `mail.${domain}`).replace(/\.$/, '').toLowerCase();
  const dkimSelector = expected.dkimSelector || 'mail';
  const expectedDkimKey = expected.dkimPublicKey?.replace(/\s+/g, '');

  const status: DnsCheckStatus = {
    aRecord: false,
    mx: false,
    spf: false,
    dkim: false,
    dmarc: false,
    lastChecked: new Date().toISOString()
  };

  const detailsList: string[] = [];

  // Use direct public nameservers (Cloudflare 1.1.1.1, Google 8.8.8.8) to bypass stale local cache
  const resolver = new Resolver();
  try {
    resolver.setServers(['1.1.1.1', '8.8.8.8', '1.0.0.1']);
  } catch {
    // fallback to system default resolver
  }

  // 1. Verify A Record (mail.<domain>)
  try {
    const aRecords = await resolver.resolve4(`mail.${domain}`);
    if (aRecords && aRecords.length > 0) {
      if (!expectedIp || aRecords.includes(expectedIp)) {
        status.aRecord = true;
        detailsList.push(`[OK] A Record (mail.${domain}): Terverifikasi pointing ke [${aRecords.join(', ')}]`);
      } else {
        detailsList.push(`[BELUM SESUAI] A Record (mail.${domain}): Terdeteksi [${aRecords.join(', ')}], namun wajib diarahkan ke IP server [${expectedIp}]`);
      }
    } else {
      detailsList.push(`[PENDING] A Record (mail.${domain}): Belum terdeteksi di DNS domain`);
    }
  } catch (err: any) {
    detailsList.push(`[PENDING] A Lookup (mail.${domain}): ${err.code === 'ENODATA' || err.code === 'ENOTFOUND' ? 'Record belum terpasang di DNS provider' : (err.code || err.message)}`);
  }

  // 2. Verify MX Record (@ -> mail.<domain>)
  try {
    const mxRecords = await resolver.resolveMx(domain);
    if (mxRecords && mxRecords.length > 0) {
      const normalizedExchanges = mxRecords.map(m => m.exchange.replace(/\.$/, '').toLowerCase());
      if (normalizedExchanges.includes(expectedMx)) {
        status.mx = true;
        detailsList.push(`[OK] MX Record (@): Terverifikasi mengarah ke [${expectedMx}]`);
      } else {
        detailsList.push(`[BELUM SESUAI] MX Record (@): Terdeteksi [${mxRecords.map(m => `${m.exchange} (prio ${m.priority})`).join(', ')}], namun wajib diarahkan ke [${expectedMx}]`);
      }
    } else {
      detailsList.push(`[PENDING] MX Record (@): Belum terdeteksi di DNS domain`);
    }
  } catch (err: any) {
    detailsList.push(`[PENDING] MX Lookup (@): ${err.code === 'ENODATA' || err.code === 'ENOTFOUND' ? 'Record belum terpasang di DNS provider' : (err.code || err.message)}`);
  }

  // 3. Verify SPF (TXT on root @)
  try {
    const txtRecords = await resolver.resolveTxt(domain);
    const joinedRecords = txtRecords.map(chunks => chunks.join(''));
    const spfRecord = joinedRecords.find(r => r.trim().toLowerCase().startsWith('v=spf1'));
    if (spfRecord) {
      const lowerSpf = spfRecord.toLowerCase();
      const matchesServer =
        !expectedIp ||
        lowerSpf.includes(`ip4:${expectedIp.toLowerCase()}`) ||
        lowerSpf.includes('mx') ||
        lowerSpf.includes(`a:mail.${domain.toLowerCase()}`);

      if (matchesServer) {
        status.spf = true;
        detailsList.push(`[OK] SPF Record (@): Terverifikasi [${spfRecord}]`);
      } else {
        detailsList.push(`[BELUM SESUAI] SPF Record (@): Terdeteksi [${spfRecord}], namun belum mengotorisasi ip4:${expectedIp}`);
      }
    } else {
      detailsList.push(`[PENDING] SPF Record (v=spf1): Belum ditemukan pada TXT record root domain`);
    }
  } catch (err: any) {
    detailsList.push(`[PENDING] SPF Lookup (@): ${err.code === 'ENODATA' || err.code === 'ENOTFOUND' ? 'Record belum terpasang di DNS provider' : (err.code || err.message)}`);
  }

  // 4. Verify DKIM (TXT on mail._domainkey.<domain>)
  try {
    const dkimHost = `${dkimSelector}._domainkey.${domain}`;
    const dkimRecords = await resolver.resolveTxt(dkimHost);
    const joinedDkim = dkimRecords.map(chunks => chunks.join('').replace(/\s+/g, ''));
    const dkim = joinedDkim.find(r => r.includes('v=DKIM1') || r.includes('p='));
    if (dkim) {
      if (!expectedDkimKey || dkim.includes(expectedDkimKey)) {
        status.dkim = true;
        detailsList.push(`[OK] DKIM Record (${dkimSelector}._domainkey): Kunci publik RSA 2048-bit terverifikasi valid`);
      } else {
        detailsList.push(`[BELUM SESUAI] DKIM Record (${dkimSelector}._domainkey): Terdeteksi TXT record, namun kunci publik RSA tidak cocok dengan yang di-generate sistem`);
      }
    } else {
      detailsList.push(`[PENDING] DKIM Record (${dkimSelector}._domainkey): Belum terdeteksi pada DNS`);
    }
  } catch (err: any) {
    detailsList.push(`[PENDING] DKIM Lookup (${dkimSelector}._domainkey): ${err.code === 'ENODATA' || err.code === 'ENOTFOUND' ? 'Record belum terpasang di DNS provider' : (err.code || err.message)}`);
  }

  // 5. Verify DMARC (TXT on _dmarc.<domain>)
  try {
    const dmarcRecords = await resolver.resolveTxt(`_dmarc.${domain}`);
    const joinedDmarc = dmarcRecords.map(chunks => chunks.join(''));
    const dmarc = joinedDmarc.find(r => r.trim().toLowerCase().startsWith('v=dmarc1'));
    if (dmarc) {
      status.dmarc = true;
      detailsList.push(`[OK] DMARC Policy (_dmarc): Terverifikasi [${dmarc}]`);
    } else {
      detailsList.push(`[PENDING] DMARC Record (_dmarc): Belum ditemukan TXT v=DMARC1`);
    }
  } catch (err: any) {
    detailsList.push(`[PENDING] DMARC Lookup (_dmarc): ${err.code === 'ENODATA' || err.code === 'ENOTFOUND' ? 'Record belum terpasang di DNS provider' : (err.code || err.message)}`);
  }

  status.details = detailsList.join('\n');
  return status;
}
