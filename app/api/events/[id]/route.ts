import { NextResponse } from 'next/server';
import { S } from '@/lib/store';
export const dynamic = 'force-dynamic';
export async function GET(_: Request, { params }: { params: { id: string } }) {
  const e = S().events.find((x: any) => x.id === params.id);
  return e ? NextResponse.json(e) : NextResponse.json({ error: 'Event not found' }, { status: 404 });
}
