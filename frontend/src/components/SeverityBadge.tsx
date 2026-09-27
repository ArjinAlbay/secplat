import type { Severity } from "@/lib/api";
import { Badge } from "@/components/ui/badge";

const LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
  unknown: "Unknown",
};

interface SeverityBadgeProps {
  severity: Severity | string;
  className?: string;
}

export default function SeverityBadge({ severity, className = "" }: SeverityBadgeProps) {
  const label = LABELS[severity as Severity] ?? severity;
  const variant = (
    ["critical", "high", "medium", "low", "info"].includes(severity)
      ? severity
      : "secondary"
  ) as "critical" | "high" | "medium" | "low" | "info" | "secondary";

  return (
    <Badge variant={variant} className={`text-[11px] font-medium ${className}`} aria-label={`Severity: ${label}`}>
      {label}
    </Badge>
  );
}
