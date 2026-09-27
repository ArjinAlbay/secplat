"use client";

import React, { type ReactNode } from "react";
import { useHelp } from "./HelpProvider";

type HelpTriggerProps = {
  title: string;
  content: ReactNode;
  className?: string;
};

export default function HelpTrigger({ title, content, className = "" }: HelpTriggerProps) {
  const { openHelp } = useHelp();

  return (
    <button
      type="button"
      className={`help-trigger ${className}`}
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        openHelp(title, content);
      }}
      aria-label={`Help about ${title}`}
      title={`Help about ${title}`}
    >
      ?
    </button>
  );
}
