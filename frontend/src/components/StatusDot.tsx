import type { ScanStatus } from "@/lib/api";

interface StatusDotProps {
  status: ScanStatus;
}

export default function StatusDot({ status }: StatusDotProps) {
  const animated = status === "running" || status === "pending" || status === "queued";
  return (
    <div className="status-dot-wrap" aria-label={status}>
      <div className={`status-dot ${status}`}>
        {animated && <div className="status-dot-pulse" />}
      </div>
    </div>
  );
}
