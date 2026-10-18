import { NextResponse } from 'next/server';
import { webhookAction } from '@/lib/store';
export const dynamic = 'force-dynamic';
export async function POST(req: Request) {
  const b = await req.json().catch(() => null);
  const r: any = webhookAction(b?.action);
  if (r.error) return NextResponse.json(r, { status: 409 });
  return NextResponse.json(r, { status: r.hook.result.startsWith('REJECTED') ? 422 : 200 });
}
