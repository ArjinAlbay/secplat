"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { ZapIcon, MenuIcon } from "@/components/icons";

interface TopBarProps {
  onToggleMobileMenu?: () => void;
}

export default function TopBar({ onToggleMobileMenu }: TopBarProps) {
  const [activeScans, setActiveScans] = useState<number>(0);

  useEffect(() => {
    let alive = true;
    async function check() {
      try {
        const count = await api.getActiveScanCount();
        if (alive) setActiveScans(count);
      } catch {
        // API offline
      }
    }
    void check();
    const interval = setInterval(() => void check(), 5000);
    return () => {
      alive = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <header className="topbar">
      <div className="topbar-left">
        <button
          type="button"
          className="topbar-mobile-btn"
          onClick={onToggleMobileMenu}
          aria-label="Toggle navigation menu"
        >
          <MenuIcon width={18} height={18} />
        </button>
        <div className="topbar-badge system-status">
          <span className="system-dot online" />
          <span className="system-text">Engine Online</span>
        </div>
      </div>

      <div className="topbar-right">
        {activeScans > 0 ? (
          <Link href="/scans" className="topbar-scan-pill active">
            <span className="topbar-pulse-dot" />
            <ZapIcon width={13} height={13} />
            <span>{activeScans} active scan{activeScans > 1 ? "s" : ""}</span>
          </Link>
        ) : (
          <div className="topbar-scan-pill idle">
            <span className="system-dot idle" />
            <span>No active scans</span>
          </div>
        )}
      </div>
    </header>
  );
}

