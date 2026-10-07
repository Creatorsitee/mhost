import { NextRequest, NextResponse } from 'next/server';
import { getDb, saveDb, EmailMessage, addAuditLog } from '@/lib/db/db';
import { simpleParser } from 'mailparser';

export const dynamic = 'force-dynamic';

/**
 * Inbound Email Webhook & MIME Receiver API
 * Supports incoming emails from Cloudflare Email Workers (raw MIME or JSON),
 * SendGrid, Mailgun, Postmark, or custom SMTP forwarders.
 */
export async function POST(req: NextRequest) {
  try {
    const contentType = req.headers.get('content-type') || '';
    let body: any = {};

    if (contentType.includes('application/json')) {
      body = await req.json();
    } else if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
      const formData = await req.formData();
      body = {
        to: formData.get('to') || formData.get('recipient'),
        from: formData.get('from') || formData.get('sender'),
        fromName: formData.get('fromName'),
        subject: formData.get('subject') || '(No Subject)',
        bodyText: formData.get('bodyText') || formData.get('text') || formData.get('body-plain') || '',
        bodyHtml: formData.get('bodyHtml') || formData.get('html') || formData.get('body-html') || '',
        raw: formData.get('raw') || formData.get('email')
      };
    } else if (contentType.includes('message/rfc822') || contentType.includes('text/plain')) {
      const rawText = await req.text();
      body = { raw: rawText };
    } else {
      body = await req.json().catch(() => ({}));
    }

    // If raw RFC822 MIME payload is provided, parse it with mailparser
    if (body.raw && typeof body.raw === 'string') {
      const parsed = await simpleParser(body.raw);
      const toList = parsed.to
        ? (Array.isArray(parsed.to) ? parsed.to : [parsed.to]).flatMap(t => t.value.map(v => v.address || '')).filter(Boolean)
        : [];
      body.to = body.to || toList;
      body.from = body.from || parsed.from?.value[0]?.address || '';
      body.fromName = body.fromName || parsed.from?.value[0]?.name;
      body.subject = body.subject || parsed.subject || '(No Subject)';
      body.bodyText = body.bodyText || parsed.text || '';
      body.bodyHtml = body.bodyHtml || (parsed.html as string) || '';
      body.messageId = body.messageId || parsed.messageId;
      if (parsed.attachments && parsed.attachments.length > 0 && !body.attachments) {
        body.attachments = parsed.attachments.map(a => ({
          filename: a.filename || 'attachment',
          contentType: a.contentType || 'application/octet-stream',
          size: a.size || a.content.length,
          content: a.content.toString('base64')
        }));
      }
    }

    const rawTo = body.to || body.recipient || '';
    const rawFrom = body.from || body.sender || '';
    const subject = body.subject || '(No Subject)';
    const text = body.bodyText || body.text || body['body-plain'] || '';
    const html = body.bodyHtml || body.html || body['body-html'] || `<div>${text.replace(/\n/g, '<br/>')}</div>`;

    if (!rawTo || (Array.isArray(rawTo) && rawTo.length === 0)) {
      return NextResponse.json({ error: 'Recipient "to" address is required' }, { status: 400 });
    }

    const recipients = Array.isArray(rawTo) ? rawTo : [rawTo];
    const db = await getDb();
    let deliveredCount = 0;

    for (const recipient of recipients) {
      // Extract clean email address
      const addressMatch = String(recipient).match(/<([^>]+)>/) || [null, String(recipient)];
      const cleanAddress = (addressMatch[1] || String(recipient)).trim().toLowerCase();

      const targetMailbox = db.data.mailboxes.find(
        m => m.fullAddress.toLowerCase() === cleanAddress && m.status === 'active'
      );
      if (targetMailbox) {
        const domain = db.data.domains.find(d => d.id === targetMailbox.domainId);
        if (!domain || domain.status !== 'active') {
          return NextResponse.json({
            success: false,
            error: `Domain ${domain?.name || ''} DNS records are not verified yet. Cannot accept inbound mail.`
          }, { status: 403 });
        }

        // Extract sender address & name
        const fromMatch = String(rawFrom).match(/^(.*?)(?:<([^>]+)>)?$/);
        const fromName = body.fromName || (fromMatch ? fromMatch[1]?.trim().replace(/^"|"$/g, '') : undefined);
        const fromAddress = fromMatch && fromMatch[2] ? fromMatch[2].trim() : String(rawFrom).trim();

        const incomingEmail: EmailMessage = {
          id: Math.random().toString(36).substring(7),
          mailboxId: targetMailbox.id,
          folder: 'inbox',
          from: {
            name: fromName || fromAddress,
            address: fromAddress
          },
          to: [cleanAddress],
          subject: subject,
          bodyText: text,
          bodyHtml: html,
          attachments: Array.isArray(body.attachments) ? body.attachments.map((a: any) => ({
            id: Math.random().toString(36).substring(7),
            filename: a.filename || 'attachment',
            contentType: a.contentType || 'application/octet-stream',
            size: a.size || Math.round((a.content?.length || 0) * 0.75),
            dataBase64: a.content || a.dataBase64
          })) : [],
          isRead: false,
          isStarred: false,
          messageId: body.messageId || `<inbound-${Date.now()}@${domain.name}>`,
          date: body.date || new Date().toISOString()
        };

        db.data.emails.push(incomingEmail);
        targetMailbox.storageUsed += (text.length || 0) + 1024;
        deliveredCount++;
        await addAuditLog('email.inbound', 'email', `Inbound email delivered to ${cleanAddress} from ${fromAddress}`);
      }
    }

    await saveDb();

    if (deliveredCount === 0) {
      return NextResponse.json({ 
        success: false, 
        message: `No active mailbox found matching address: ${recipients.join(', ')}` 
      }, { status: 404 });
    }

    return NextResponse.json({
      success: true,
      deliveredTo: deliveredCount,
      message: `Delivered to ${deliveredCount} mailbox(es)`
    });
  } catch (error: any) {
    console.error('Inbound webhook error:', error);
    return NextResponse.json({ error: error.message || 'Internal processing error' }, { status: 500 });
  }
}
