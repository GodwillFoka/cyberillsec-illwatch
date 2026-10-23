import { ChevronLeft, ChevronRight } from "lucide-react";

import { messages } from "../i18n/common.i18n";
import { formatNumber } from "../lib/format";

/** Pagination « précédents / suivants » d'une liste longue (IOC, CVE). */
export function Pager({
  offset,
  shown,
  total,
  pageSize,
  busy,
  onOffset,
}: {
  offset: number;
  shown: number;
  total: number;
  pageSize: number;
  busy: boolean;
  onOffset: (offset: number) => void;
}) {
  if (total <= pageSize && offset === 0) return null;
  return (
    <div className="pager">
      <span className="muted">
        {messages("pagerRange", {
          from: formatNumber(offset + 1),
          to: formatNumber(offset + shown),
          total: formatNumber(total),
        })}
        {busy ? messages("pagerReading") : ""}
      </span>
      <div className="row">
        <button
          className="btn"
          type="button"
          disabled={offset === 0 || busy}
          onClick={() => onOffset(Math.max(0, offset - pageSize))}
        >
          <ChevronLeft size={16} aria-hidden="true" />
          {messages("previous")}
        </button>
        <button
          className="btn"
          type="button"
          disabled={offset + shown >= total || busy}
          onClick={() => onOffset(offset + pageSize)}
        >
          {messages("next")}
          <ChevronRight size={16} aria-hidden="true" />
        </button>
      </div>
    </div>
  );
}
