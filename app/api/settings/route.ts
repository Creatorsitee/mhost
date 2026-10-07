import { NextRequest, NextResponse } from 'next/server';
import { getDb, saveDb, initializeSystem } from '@/lib/db/db';
import { getSession } from '@/lib/auth';

export async function GET() {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  await initializeSystem();
  const db = await getDb();
  return NextResponse.json(db.data.settings);
}

export async function POST(req: NextRequest) {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const body = await req.json();
  const db = await getDb();
  
  const newServerIp = body.serverIp ? String(body.serverIp).trim() : db.data.settings.serverIp;

  db.data.settings = {
    ...db.data.settings,
    ...body,
    serverIp: newServerIp,
    setupCompleted: true
  };

  // Sync domains' expected A and SPF records if serverIp was updated
  if (newServerIp && newServerIp !== '0.0.0.0') {
    for (const domain of db.data.domains) {
      domain.dnsConfig.mailServerIp = newServerIp;
      (domain.dnsConfig as any).a = {
        host: 'mail',
        value: newServerIp
      };
      domain.dnsConfig.spf = `v=spf1 ip4:${newServerIp} ~all`;
    }
  }
  
  await saveDb();
  return NextResponse.json({ success: true, settings: db.data.settings });
}
