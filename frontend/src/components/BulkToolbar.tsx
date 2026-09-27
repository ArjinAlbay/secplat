"use client";

import { TrashIcon, XIcon } from "@/components/icons";

interface BulkToolbarProps {
  selectedCount: number;
  totalCount?: number;
  onClearSelection: () => void;
  onDeleteSelected: () => void;
  isDeleting?: boolean;
  entityName?: string;
}

export default function BulkToolbar({
  selectedCount,
  onClearSelection,
  onDeleteSelected,
  isDeleting = false,
  entityName = "items",
}: BulkToolbarProps) {
  if (selectedCount === 0) return null;

  return (
    <div className="bulk-toolbar" role="toolbar" aria-label="Bulk actions toolbar">
      <div className="bulk-toolbar-info">
        <span className="bulk-badge">{selectedCount}</span>
        <span className="bulk-label">
          {entityName} selected
        </span>
      </div>

      <div className="bulk-toolbar-actions">
        <button
          type="button"
          className="btn btn-danger btn-sm"
          onClick={onDeleteSelected}
          disabled={isDeleting}
        >
          <TrashIcon width={13} height={13} />
          {isDeleting ? "Deleting…" : `Delete selected (${selectedCount})`}
        </button>

        <button
          type="button"
          className="btn btn-ghost btn-sm"
          onClick={onClearSelection}
          disabled={isDeleting}
          title="Clear selection"
        >
          <XIcon width={13} height={13} />
          Cancel
        </button>
      </div>
    </div>
  );
}

