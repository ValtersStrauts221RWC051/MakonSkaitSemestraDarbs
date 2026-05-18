import { useCallback, useEffect, useState } from "react";
import { api } from "./api/client";
import { AnalysesTable } from "./components/AnalysesTable";
import { CountryMap } from "./components/CountryMap";
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
  CountryStat,
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
  const [countries, setCountries] = useState<CountryStat[]>([]);
  const [enriching, setEnriching] = useState(false);
  const [analyses, setAnalyses] = useState<Analysis[]>([]);
  const [analysesTotal, setAnalysesTotal] = useState(0);
  const [filters, setFilters] = useState<AnalysesFilters>({ limit: 25, offset: 0 });
  const [selected, setSelected] = useState<Analysis | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [s, t, h, p, qt, co, a] = await Promise.all([
        api.stats(),
        api.topSuspicious(10),
        api.hourly(24),
        api.parents(10),
        api.types(),
        api.countries(),
        api.analyses(filters),
      ]);
      setStats(s);
      setTop(t);
      setHourly(h);
      setParents(p);
      setTypes(qt);
      setCountries(co);
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

  async function runEnrich() {
    setEnriching(true);
    try {
      await api.enrich(10);
      await load();
    } finally {
      setEnriching(false);
    }
  }

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

        <div style={{ marginBottom: 16 }}>
          <CountryMap data={countries} />
          <div style={{ textAlign: "right", marginTop: 8 }}>
            <button className="secondary" onClick={runEnrich} disabled={enriching}>
              {enriching ? "Enriching…" : "Enrich next 10 domains"}
            </button>
          </div>
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
