import { NextResponse } from 'next/server';
import { S, setConfig } from '@/lib/store';
export const dynamic = 'force-dynamic';
export async function GET() { return NextResponse.json(S().cfg); }
export async function PUT(req: Request) {
  const b = await req.json().catch(() => null);
  if (!setConfig(b)) return NextResponse.json({ error: 'Invalid config: weights/threshold must be 0-100, windowSec 10-3600' }, { status: 400 });
  return NextResponse.json(S().cfg);
}
