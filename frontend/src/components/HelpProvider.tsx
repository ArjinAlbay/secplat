"use client";

import React, { createContext, useContext, useState, useCallback, type ReactNode } from "react";
import HelpDrawer from "./HelpDrawer";

type HelpContextType = {
  isOpen: boolean;
  openHelp: (title: string, content: ReactNode) => void;
  closeHelp: () => void;
};

const HelpContext = createContext<HelpContextType | undefined>(undefined);

export function HelpProvider({ children }: { children: ReactNode }) {
  const [isOpen, setIsOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [content, setContent] = useState<ReactNode>(null);

  const openHelp = useCallback((newTitle: string, newContent: ReactNode) => {
    setTitle(newTitle);
    setContent(newContent);
    setIsOpen(true);
  }, []);

  const closeHelp = useCallback(() => {
    setIsOpen(false);
    // Don't clear content immediately to allow smooth exit animation
    setTimeout(() => {
      setContent(null);
      setTitle("");
    }, 300);
  }, []);

  return (
    <HelpContext.Provider value={{ isOpen, openHelp, closeHelp }}>
      {children}
      <HelpDrawer isOpen={isOpen} title={title} content={content} onClose={closeHelp} />
    </HelpContext.Provider>
  );
}

export function useHelp() {
  const context = useContext(HelpContext);
  if (!context) {
    throw new Error("useHelp must be used within a HelpProvider");
  }
  return context;
}
