"use client";

import { useState, type ReactNode } from "react";
import Sidebar from "@/components/Sidebar";
import TopBar from "@/components/TopBar";

export default function AppShell({ children }: { children: ReactNode }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div className="shell">
      <Sidebar
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />
      <div className="shell-main">
        <TopBar onToggleMobileMenu={() => setMobileMenuOpen((v) => !v)} />
        <main className="container">{children}</main>
      </div>
    </div>
  );
}

