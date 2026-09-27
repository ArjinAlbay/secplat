"use client";

import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export type TabItem<T extends string = string> = {
  id: T;
  label: string;
  icon?: ReactNode;
  count?: number | null;
  badgeVariant?: "default" | "critical" | "high" | "accent";
};

interface TabsProps<T extends string = string> {
  tabs: TabItem<T>[];
  activeTab: T;
  onChange: (tabId: T) => void;
  ariaLabel?: string;
  variant?: "line" | "pill";
}

export default function Tabs<T extends string = string>({
  tabs,
  activeTab,
  onChange,
  ariaLabel = "Navigation Tabs",
  variant = "line",
}: TabsProps<T>) {
  if (variant === "pill") {
    return (
      <div
        className="inline-flex h-8 items-center justify-center rounded-md bg-muted/40 p-1 text-muted-foreground mb-4 border border-border"
        role="tablist"
        aria-label={ariaLabel}
      >
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              aria-controls={`panel-${tab.id}`}
              id={`tab-${tab.id}`}
              className={cn(
                "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-sm px-2.5 py-1 text-xs font-medium transition-all",
                isActive
                  ? "bg-card text-foreground shadow-xs font-semibold"
                  : "text-muted-foreground hover:text-foreground"
              )}
              onClick={() => onChange(tab.id)}
            >
              {tab.icon && <span className="opacity-75">{tab.icon}</span>}
              <span>{tab.label}</span>
              {tab.count != null && tab.count >= 0 && (
                <span className="rounded-full bg-muted px-1.5 py-0.2 text-[10px] font-semibold text-muted-foreground">
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>
    );
  }

  return (
    <div
      className="flex items-center gap-2 border-b border-border mb-5"
      role="tablist"
      aria-label={ariaLabel}
    >
      {tabs.map((tab) => {
        const isActive = activeTab === tab.id;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={isActive}
            aria-controls={`panel-${tab.id}`}
            id={`tab-${tab.id}`}
            className={cn(
              "inline-flex items-center gap-2 px-3 py-2 text-xs font-medium border-b-2 -mb-px transition-colors",
              isActive
                ? "border-primary text-foreground font-semibold"
                : "border-transparent text-muted-foreground hover:text-foreground"
            )}
            onClick={() => onChange(tab.id)}
          >
            {tab.icon && <span className="opacity-75">{tab.icon}</span>}
            <span>{tab.label}</span>
            {tab.count != null && tab.count >= 0 && (
              <span
                className={cn(
                  "rounded-full px-1.5 py-0.2 text-[10px] font-semibold",
                  tab.badgeVariant === "critical"
                    ? "bg-destructive/15 text-destructive"
                    : tab.badgeVariant === "high"
                    ? "bg-amber-500/15 text-amber-400"
                    : tab.badgeVariant === "accent"
                    ? "bg-primary/15 text-primary"
                    : "bg-muted text-muted-foreground"
                )}
              >
                {tab.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
