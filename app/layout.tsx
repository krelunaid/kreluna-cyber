import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { headers } from "next/headers";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const host =
    requestHeaders.get("x-forwarded-host") ??
    requestHeaders.get("host") ??
    "creluna-vault-lab.andreagadducci.chatgpt.site";
  const protocol =
    requestHeaders.get("x-forwarded-proto") ??
    (host.startsWith("localhost") ? "http" : "https");
  const origin = `${protocol}://${host}`;

  return {
    title: "Creluna Cyber · The Vault Challenge",
    description:
      "The live defensive command center protecting an isolated challenge server.",
    metadataBase: new URL(origin),
    openGraph: {
      title: "Creluna Cyber · The Vault Challenge",
      description:
        "Five defensive agents. One isolated vault. Every decision audited.",
      type: "website",
      images: [
        {
          url: `${origin}/og.png`,
          width: 1672,
          height: 941,
          alt: "Creluna Cyber — The Vault Challenge",
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title: "Creluna Cyber · The Vault Challenge",
      description:
        "Five defensive agents. One isolated vault. Every decision audited.",
      images: [`${origin}/og.png`],
    },
  };
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="it">
      <body className={`${geistSans.variable} ${geistMono.variable}`}>
        {children}
      </body>
    </html>
  );
}
