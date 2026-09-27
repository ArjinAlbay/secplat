"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import {
  ShieldIcon,
  HomeIcon,
  FolderIcon,
  ActivityIcon,
  FileIcon,
  WrenchIcon,
  XIcon,
} from "@/components/icons";

type NavItem = {
  label: string;
  href: string;
  icon: React.ReactNode;
  badge?: number | null;
};

interface SidebarProps {
  mobileOpen?: boolean;
  onCloseMobile?: () => void;
}

export default function Sidebar({ mobileOpen, onCloseMobile }: SidebarProps) {
  const pathname = usePathname();
  const [activeScanCount, setActiveScanCount] = useState<number | null>(null);

  useEffect(() => {
    let alive = true;
    async function load() {
      try {
        const count = await api.getActiveScanCount();
        if (alive) setActiveScanCount(count);
      } catch {
        // api offline
      }
    }
    void load();
    const interval = setInterval(() => void load(), 5000);
    return () => {
      alive = false;
      clearInterval(interval);
    };
  }, []);

  const navItems: NavItem[] = [
    {
      label: "Dashboard",
      href: "/",
      icon: <HomeIcon className="side-item-icon" width={16} height={16} />,
    },
    {
      label: "Projects",
      href: "/projects",
      icon: <FolderIcon className="side-item-icon" width={16} height={16} />,
    },
    {
      label: "Scans",
      href: "/scans",
      icon: <ActivityIcon className="side-item-icon" width={16} height={16} />,
      badge: activeScanCount && activeScanCount > 0 ? activeScanCount : null,
    },
    {
      label: "Reports",
      href: "/reports",
      icon: <FileIcon className="side-item-icon" width={16} height={16} />,
    },
  ];

  const tools = [
    { name: "nuclei", type: "DAST" },
    { name: "semgrep", type: "SAST" },
    { name: "trivy", type: "SCA / IaC" },
    { name: "gitleaks", type: "Secrets" },
    { name: "subfinder", type: "Recon" },
  ];

  function isActive(href: string) {
    if (href === "/") return pathname === "/";
    return pathname === href || pathname.startsWith(href + "/");
  }

  return (
    <>
      {mobileOpen && <div className="sidebar-backdrop" onClick={onCloseMobile} />}
      <aside className={`sidebar${mobileOpen ? " mobile-open" : ""}`}>
        {/* ── Brand ─────────────────────────────────────────────────── */}
        <div className="side-header">
          <Link href="/" className="side-brand" onClick={onCloseMobile}>
            <div className="side-brand-icon">
              <ShieldIcon strokeWidth={2} />
            </div>
            <div className="side-brand-text">
              <span className="side-brand-name">SecPlat</span>
              <span className="side-brand-sub">ASPM Platform</span>
            </div>
          </Link>
          {mobileOpen && (
            <button
              type="button"
              className="side-mobile-close"
              onClick={onCloseMobile}
              aria-label="Close menu"
            >
              <XIcon width={16} height={16} />
            </button>
          )}
        </div>

        {/* ── Primary nav ───────────────────────────────────────────── */}
        <nav className="side-nav">
          <div className="side-section">
            <div className="side-title">Main Navigation</div>
            {navItems.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={`side-item${isActive(item.href) ? " active" : ""}`}
                onClick={onCloseMobile}
              >
                {item.icon}
                <span className="side-item-label">{item.label}</span>
                {item.badge != null && (
                  <span className="side-item-badge">
                    {item.badge}
                  </span>
                )}
              </Link>
            ))}
          </div>

          {/* ── Scanner Engine Status ──────────────────────────────────── */}
          <div className="side-section">
            <div className="side-title">Engine Adapters</div>
            <div className="side-tools-grid">
              {tools.map((t) => (
                <div key={t.name} className="side-tool-chip">
                  <span className="side-tool-dot online" />
                  <span className="side-tool-name">{t.name}</span>
                  <span className="side-tool-type">{t.type}</span>
                </div>
              ))}
            </div>
          </div>

          {/* ── Roadmap / Upcoming ────────────────────────────────────── */}
          <div className="side-section" style={{ marginTop: "auto" }}>
            <div className="side-title">Coming Soon</div>
            <div
              className="side-item disabled"
              title="Work in progress (Roadmap)"
            >
              <WrenchIcon className="side-item-icon" width={16} height={16} />
              <span className="side-item-label">Settings & RBAC</span>
              <span className="side-soon-tag">v2</span>
            </div>
          </div>
        </nav>

        {/* ── Footer ────────────────────────────────────────────────── */}
        <div className="side-footer">
          <span>SecPlat v1.0 · Open Source ASPM</span>
        </div>
      </aside>
    </>
  );
}
