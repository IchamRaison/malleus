import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Malleus Studio",
  description: "Local interactive lab for Malleus live security runs"
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
