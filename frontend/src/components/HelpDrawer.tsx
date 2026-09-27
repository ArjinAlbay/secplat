"use client";

import React, { useEffect, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

type HelpDrawerProps = {
  isOpen: boolean;
  title: string;
  content: ReactNode;
  onClose: () => void;
};

export default function HelpDrawer({ isOpen, title, content, onClose }: HelpDrawerProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Prevent scrolling on body when drawer is open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "";
    }
    return () => {
      document.body.style.overflow = "";
    };
  }, [isOpen]);

  // Handle escape key
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!mounted) return null;

  return createPortal(
    <div className={`help-drawer-overlay ${isOpen ? "open" : ""}`} onClick={onClose}>
      <div
        className={`help-drawer-panel ${isOpen ? "open" : ""}`}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="help-drawer-title"
      >
        <div className="help-drawer-header">
          <h2 id="help-drawer-title">{title}</h2>
          <button className="help-drawer-close" onClick={onClose} aria-label="Close help">
            ✕
          </button>
        </div>
        <div className="help-drawer-content">{content}</div>
      </div>
    </div>,
    document.body,
  );
}
