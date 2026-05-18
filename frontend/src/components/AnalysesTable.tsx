import { useEffect, useState } from "react";
import { queryTypeLabel } from "../labels";
import type { Analysis, AnalysesFilters, QueryTypeCount } from "../types";

interface Props {
  data: Analysis[];
  total: number;
  filters: AnalysesFilters;
  setFilters: (f: AnalysesFilters) => void;
  onSelect: (a: Analysis) => void;
  types: QueryTypeCount[];
}

type SortKey = "created_at" | "score" | "query_name" | "client_ip" | "subdomain_depth";

export function AnalysesTable({ data, total, filters, setFilters, onSelect, types }: Props) {
  const limit = filters.limit ?? 25;
  const offset = filters.offset ?? 0;
  const [searchInput, setSearchInput] = useState(filters.q ?? "");
  const [sortKey, setSortKey] = useState<SortKey>("created_at");
  const [sortAsc, setSortAsc] = useState(false);

  useEffect(() => {
    const id = setTimeout(() => {
      if ((filters.q ?? "") !== searchInput) {
        setFilters({ ...filters, q: searchInput || undefined, offset: 0 });
      }
    }, 350);
    return () => clearTimeout(id);
  }, [searchInput]);

  const sorted = [...data].sort((a, b) => {
    const va = a[sortKey] as any;
    const vb = b[sortKey] as any;
    const cmp = va < vb ? -1 : va > vb ? 1 : 0;
    return sortAsc ? cmp : -cmp;
  });

  function toggleSort(k: SortKey) {
    if (sortKey === k) setSortAsc(!sortAsc);
    else { setSortKey(k); setSortAsc(false); }
  }

  function downloadCsv() {
    const headers = ["id","created_at","client_ip","query_type","query_name","parent_domain","subdomain_depth","rcode","score","alerted"];
    const lines = [headers.join(",")];
    data.forEach((r) => {
      const row = headers.map((h) => {
        const v = (r as any)[h];
        const s = String(v ?? "").replace(/"/g, '""');
        return /[,"\n]/.test(s) ? `"${s}"` : s;
      });
      lines.push(row.join(","));
    });
    const blob = new Blob([lines.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `analyses-${new Date().toISOString().slice(0, 19)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="panel">
      <h2>Recent analyses</h2>
      <div className="toolbar">
        <input
          placeholder="Search query name or client IP…"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
        />
        <select
          value={filters.query_type ?? ""}
          onChange={(e) =>
            setFilters({ ...filters, query_type: e.target.value || undefined, offset: 0 })
          }
        >
          <option value="">All types</option>
          {types.map((t) => (
            <option key={t.query_type} value={t.query_type}>
              {queryTypeLabel(t.query_type)} ({t.count})
            </option>
          ))}
        </select>
        <select
          value={filters.alerted === undefined ? "" : String(filters.alerted)}
          onChange={(e) => {
            const v = e.target.value;
            setFilters({
              ...filters,
              alerted: v === "" ? undefined : v === "true",
              offset: 0,
            });
          }}
        >
          <option value="">All</option>
          <option value="true">Alerts only</option>
          <option value="false">Safe only</option>
        </select>
        <button className="secondary" onClick={downloadCsv}>Export CSV</button>
      </div>

      {sorted.length === 0 ? (
        <div className="empty">No matching analyses</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th className="sortable" onClick={() => toggleSort("created_at")}>Time {sortKey === "created_at" ? (sortAsc ? "↑" : "↓") : ""}</th>
              <th className="sortable" onClick={() => toggleSort("client_ip")}>Client {sortKey === "client_ip" ? (sortAsc ? "↑" : "↓") : ""}</th>
              <th>Type</th>
              <th className="sortable" onClick={() => toggleSort("query_name")}>Query {sortKey === "query_name" ? (sortAsc ? "↑" : "↓") : ""}</th>
              <th className="sortable" onClick={() => toggleSort("subdomain_depth")}>Depth</th>
              <th className="sortable" onClick={() => toggleSort("score")}>Score {sortKey === "score" ? (sortAsc ? "↑" : "↓") : ""}</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((r) => (
              <tr key={r.id} className={`clickable ${r.alerted ? "alert" : ""}`} onClick={() => onSelect(r)}>
                <td>{r.created_at.slice(0, 19).replace("T", " ")}</td>
                <td>{r.client_ip}</td>
                <td title={r.query_type}>{queryTypeLabel(r.query_type)}</td>
                <td title={r.query_name} style={{ maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {r.query_name}
                </td>
                <td>{r.subdomain_depth}</td>
                <td>{r.score.toFixed(4)}</td>
                <td>
                  <span className={`pill ${r.alerted ? "alert" : "safe"}`}>
                    {r.alerted ? "Alert" : "Safe"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="pager">
        <span>Total: {total} · Showing {offset + 1}–{Math.min(offset + limit, total)}</span>
        <button
          disabled={offset === 0}
          onClick={() => setFilters({ ...filters, offset: Math.max(0, offset - limit) })}
        >
          ← Prev
        </button>
        <button
          disabled={offset + limit >= total}
          onClick={() => setFilters({ ...filters, offset: offset + limit })}
        >
          Next →
        </button>
      </div>
    </div>
  );
}
