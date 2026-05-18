import { useCallback, useEffect, useState } from "react";
import { api } from "./api/client";
import { AnalysesTable } from "./components/AnalysesTable";
import { DetailModal } from "./components/DetailModal";
import { HourlyChart } from "./components/HourlyChart";
import { QueryTypeChart } from "./components/QueryTypeChart";
import { StatsCards } from "./components/StatsCards";
import { TopDomainsChart } from "./components/TopDomainsChart";
import { TopSuspiciousChart } from "./components/TopSuspiciousChart";
import { useAutoRefresh } from "./hooks/useAutoRefresh";
import type {
  Analysis,
  AnalysesFilters,
  HourlyBucket,
  ParentDist,
  QueryTypeCount,
  Stats,
  TopSuspicious,
} from "./types";

export default function App() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [top, setTop] = useState<TopSuspicious[]>([]);
  const [hourly, setHourly] = useState<HourlyBucket[]>([]);
  const [parents, setParents] = useState<ParentDist[]>([]);
  const [types, setTypes] = useState<QueryTypeCount[]>([]);
  const [analyses, setAnalyses] = useState<Analysis[]>([]);
  const [analysesTotal, setAnalysesTotal] = useState(0);
  const [filters, setFilters] = useState<AnalysesFilters>({ limit: 25, offset: 0 });
  const [selected, setSelected] = useState<Analysis | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [s, t, h, p, qt, a] = await Promise.all([
        api.stats(),
        api.topSuspicious(10),
        api.hourly(24),
        api.parents(10),
        api.types(),
        api.analyses(filters),
      ]);
      setStats(s);
      setTop(t);
      setHourly(h);
      setParents(p);
      setTypes(qt);
      setAnalyses(a.items);
      setAnalysesTotal(a.total);
      setLastUpdate(new Date());
      setError(null);
    } catch (e: any) {
      setError(e.message || "Failed to load");
    }
  }, [filters]);

  useEffect(() => { load(); }, [load]);
  useAutoRefresh(load, autoRefresh, 5000);

  return (
    <>
      <header>
        <h1>DNS Security Dashboard</h1>
        <div className="meta">
          {error && <span style={{ color: "#ffb4b4" }}>⚠ {error}</span>}
          <label className="switch">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            Auto-refresh
          </label>
          <button className="secondary" onClick={load}>Refresh</button>
          {lastUpdate && <span>{lastUpdate.toLocaleTimeString()}</span>}
        </div>
      </header>
      <main>
        <StatsCards stats={stats} threshold={stats?.threshold ?? 0} />

        <div className="row">
          <HourlyChart data={hourly} />
          <TopSuspiciousChart data={top} />
        </div>

        <div className="row">
          <TopDomainsChart data={parents} />
          <QueryTypeChart data={types} />
        </div>

        <AnalysesTable
          data={analyses}
          total={analysesTotal}
          filters={filters}
          setFilters={setFilters}
          onSelect={setSelected}
          types={types}
        />
      </main>

      {selected && <DetailModal record={selected} onClose={() => setSelected(null)} />}
    </>
  );
}
