import type { ReactNode } from "react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface KpiCardProps {
  label: string;
  value: string | number;
  sublabel?: string;
  icon?: ReactNode;
  variant?: "default" | "critical" | "high" | "warning" | "success" | "accent";
  badge?: string;
  onClick?: () => void;
  className?: string;
}

export default function KpiCard({
  label,
  value,
  sublabel,
  icon,
  variant = "default",
  badge,
  onClick,
  className = "",
}: KpiCardProps) {
  const isClickable = !!onClick;

  return (
    <Card
      className={cn(
        "transition-colors",
        isClickable && "cursor-pointer hover:bg-secondary/60 hover:border-border/80",
        className
      )}
      onClick={onClick}
      role={isClickable ? "button" : undefined}
      tabIndex={isClickable ? 0 : undefined}
      onKeyDown={
        isClickable
          ? (e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onClick();
              }
            }
          : undefined
      }
    >
      <CardHeader className="flex flex-row items-center justify-between p-4 pb-2 space-y-0">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          {label}
        </span>
        {icon && <span className="text-muted-foreground/70">{icon}</span>}
      </CardHeader>
      <CardContent className="p-4 pt-0 flex flex-col gap-1">
        <div className="flex items-baseline gap-2">
          <span
            className={cn(
              "text-2xl font-bold tracking-tight text-foreground",
              variant === "critical" && Number(value) > 0 && "text-red-400"
            )}
          >
            {value}
          </span>
          {badge && (
            <span className="rounded-full bg-secondary px-2 py-0.5 text-[10px] font-medium text-muted-foreground border border-border">
              {badge}
            </span>
          )}
        </div>
        {sublabel && (
          <div className="text-xs text-muted-foreground">{sublabel}</div>
        )}
      </CardContent>
    </Card>
  );
}
