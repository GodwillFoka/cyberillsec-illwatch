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
        {formatNumber(offset + 1)}–{formatNumber(offset + shown)} sur {formatNumber(total)}
        {busy ? " · lecture…" : ""}
      </span>
      <div className="row">
        <button
          className="btn"
          type="button"
          disabled={offset === 0 || busy}
          onClick={() => onOffset(Math.max(0, offset - pageSize))}
        >
          ← Précédents
        </button>
        <button
          className="btn"
          type="button"
          disabled={offset + shown >= total || busy}
          onClick={() => onOffset(offset + pageSize)}
        >
          Suivants →
        </button>
      </div>
    </div>
  );
}
