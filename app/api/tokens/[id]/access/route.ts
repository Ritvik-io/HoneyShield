import { NextResponse } from 'next/server';
import { accessToken } from '@/lib/store';
export const dynamic = 'force-dynamic';
export async function POST(_: Request, { params }: { params: { id: string } }) {
  await new Promise(r => setTimeout(r, 600)); // brief delay so the UI loading state is visible in the demo
  const r = accessToken(params.id);
  if (!r) return NextResponse.json({ error: 'Token not found' }, { status: 404 });
  return NextResponse.json(r);
}
