import { SMTPServer } from 'smtp-server';
import { simpleParser } from 'mailparser';
import { getDb, saveDb, type EmailMessage, addAuditLog } from '../db/db.ts';

/**
 * LOCAL SMTP RECEIVER (MTA)
 * Receives incoming SMTP traffic on Port 2525 (or forwarded from Port 25)
 * and stores real emails directly into the verified domain's mailbox inbox in db.json.
 */

export const startInternalSmtpServer = () => {
  try {
    const server = new SMTPServer({
      authOptional: true,
      size: 25 * 1024 * 1024, // 25MB max message size
      onRcptTo(address, session, callback) {
        const cleanAddress = address.address.trim().toLowerCase();
        getDb()
          .then((db) => {
            const mailbox = db.data.mailboxes.find(
              (m) => m.fullAddress.toLowerCase() === cleanAddress && m.status === 'active'
            );
            if (!mailbox) {
              return callback(new Error(`550 5.1.1 <${cleanAddress}>: Recipient address rejected: User unknown`));
            }
            const domain = db.data.domains.find((d) => d.id === mailbox.domainId);
            if (!domain || domain.status !== 'active') {
              return callback(new Error(`451 4.3.0 <${cleanAddress}>: Domain DNS records are not fully verified yet`));
            }
            callback();
          })
          .catch(() => callback());
      },
      onData(stream, session, callback) {
        simpleParser(stream, async (err, parsed) => {
          if (err) return callback(err);

          try {
            const db = await getDb();
            const toField = parsed.to;
            const ccField = parsed.cc;

            const extractAddresses = (field: any): string[] => {
              if (!field) return [];
              const list = Array.isArray(field) ? field : [field];
              const addrs: string[] = [];
              for (const item of list) {
                if (Array.isArray(item.value)) {
                  for (const v of item.value) {
                    if (v.address) addrs.push(v.address.trim().toLowerCase());
                  }
                } else if (item.text) {
                  addrs.push(item.text.trim().toLowerCase());
                }
              }
              return addrs;
            };

            const toAddresses = extractAddresses(toField);
            const ccAddresses = extractAddresses(ccField);
            const envelopeRecipients = session.envelope.rcptTo.map((r) => r.address.trim().toLowerCase());
            const allTargetAddresses = Array.from(new Set([...toAddresses, ...ccAddresses, ...envelopeRecipients]));

            for (const address of allTargetAddresses) {
              const mailbox = db.data.mailboxes.find(
                (m) => m.fullAddress.toLowerCase() === address && m.status === 'active'
              );
              if (!mailbox) continue;

              const domain = db.data.domains.find((d) => d.id === mailbox.domainId);
              if (!domain || domain.status !== 'active') continue;

              const attachments = (parsed.attachments || []).map((att) => ({
                id: Math.random().toString(36).substring(7),
                filename: att.filename || 'attachment',
                contentType: att.contentType || 'application/octet-stream',
                size: att.size || att.content.length,
                dataBase64: att.content.toString('base64')
              }));

              const newEmail: EmailMessage = {
                id: Math.random().toString(36).substring(7),
                mailboxId: mailbox.id,
                folder: 'inbox',
                from: {
                  name: parsed.from?.value[0]?.name || parsed.from?.value[0]?.address,
                  address: parsed.from?.value[0]?.address || 'unknown@sender.com'
                },
                to: toAddresses.length > 0 ? toAddresses : [address],
                cc: ccAddresses.length > 0 ? ccAddresses : undefined,
                subject: parsed.subject || '(No Subject)',
                bodyText: parsed.text || '',
                bodyHtml: (parsed.html as string) || `<div>${(parsed.text || '').replace(/\n/g, '<br/>')}</div>`,
                attachments: attachments.length > 0 ? attachments : undefined,
                isRead: false,
                isStarred: false,
                messageId: parsed.messageId || `<${Date.now()}@${domain.name}>`,
                date: parsed.date ? parsed.date.toISOString() : new Date().toISOString(),
                inReplyTo: parsed.inReplyTo
              };

              db.data.emails.push(newEmail);
              const attachmentBytes = attachments.reduce((sum, a) => sum + a.size, 0);
              mailbox.storageUsed += (parsed.text?.length || 0) + attachmentBytes + 1024;
              await saveDb();
              await addAuditLog('email.received', 'email', `Received SMTP message for ${address} from ${newEmail.from.address}`);
            }
          } catch (e) {
            console.error('Error storing received email:', e);
          }

          callback();
        });
      },
      disabledCommands: ['AUTH']
    });

    const port = parseInt(process.env.INTERNAL_SMTP_PORT || '2525', 10);
    server.on('error', (err: any) => {
      if (err.code === 'EADDRINUSE') {
        console.log(`Internal SMTP Receiver already active on port ${port}`);
      } else {
        console.error('SMTP Server error:', err);
      }
    });
    server.listen(port, '0.0.0.0', () => {
      console.log(`Internal SMTP Receiver listening on port ${port}`);
    });
  } catch (err) {
    console.error('Could not start internal SMTP server:', err);
  }
};

