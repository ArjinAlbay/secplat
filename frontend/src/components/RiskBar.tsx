import type { Severity } from "@/lib/api";

const SEVERITY_KEYS: Severity[] = ["critical", "high", "medium", "low", "info"];

interface RiskBarProps {
  counts?: Record<string, number> | null;
  total?: number;
  height?: number;
  showLabels?: boolean;
}

export default function RiskBar({
  counts = {},
  total,
  height = 6,
  showLabels = false,
}: RiskBarProps) {
  const safeCounts = counts ?? {};
  const calculatedTotal =
    total ??
    Object.values(safeCounts).reduce((sum, n) => sum + (typeof n === "number" ? n : 0), 0);

  if (calculatedTotal === 0) {
    return (
      <div className="risk-bar-wrap">
        <div className="risk-bar" style={{ height }}>
          <div className="risk-segment clean" style={{ width: "100%" }} title="No findings detected" />
        </div>
        {showLabels && <span className="risk-bar-clean-label">Clean</span>}
      </div>
    );
  }

  return (
    <div className="risk-bar-wrap">
      <div className="risk-bar" style={{ height }}>
        {SEVERITY_KEYS.map((sev) => {
          const count = safeCounts[sev] ?? 0;
          if (count <= 0) return null;
          const percent = (count / calculatedTotal) * 100;
          return (
            <div
              key={sev}
              className={`risk-segment sev-${sev}`}
              style={{ width: `${percent}%` }}
              title={`${count} ${sev} findings (${Math.round(percent)}%)`}
            />
          );
        })}
      </div>
      {showLabels && (
        <div className="risk-bar-legend">
          {SEVERITY_KEYS.map((sev) => {
            const count = safeCounts[sev] ?? 0;
            if (count <= 0) return null;
            return (
              <span key={sev} className={`risk-legend-item sev-${sev}`}>
                <span className="risk-legend-dot" />
                {count} {sev}
              </span>
            );
          })}
        </div>
      )}
    </div>
  );
}

