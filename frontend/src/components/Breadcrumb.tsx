import Link from "next/link";
import { ChevronRightIcon } from "@/components/icons";

interface BreadcrumbItem {
  label: string;
  href?: string;
}

interface BreadcrumbProps {
  items: BreadcrumbItem[];
}

export default function Breadcrumb({ items }: BreadcrumbProps) {
  return (
    <nav className="breadcrumb" aria-label="Breadcrumb">
      {items.map((item, index) => {
        const isLast = index === items.length - 1;
        return (
          <span key={index} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            {index > 0 && (
              <ChevronRightIcon
                className="breadcrumb-sep"
                width={12}
                height={12}
                strokeWidth={2.5}
              />
            )}
            {isLast || !item.href ? (
              <span className={isLast ? "breadcrumb-current" : ""}>{item.label}</span>
            ) : (
              <Link href={item.href}>{item.label}</Link>
            )}
          </span>
        );
      })}
    </nav>
  );
}
