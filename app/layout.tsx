import './globals.css';
export const metadata = { title: 'HoneyShield', description: 'Detect Early. Respond Intelligently. Protect Sensitive Data.' };
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
