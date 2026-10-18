import { NextResponse } from 'next/server';
import { act } from '@/lib/store';
export const dynamic = 'force-dynamic';
export async function POST(req: Request, { params }: { params: { id: string } }) {
  const b = await req.json().catch(() => ({}));
  const r: any = act(params.id, b.action, b.confirm === true);
  return NextResponse.json(r.error ? { error: r.error } : r.event, { status: r.code });
}
