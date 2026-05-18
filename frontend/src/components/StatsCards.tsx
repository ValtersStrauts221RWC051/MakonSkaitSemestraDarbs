import type { Stats } from "../types";

export function StatsCards({ stats, threshold }: { stats: Stats | null; threshold: number }) {
  const s = stats ?? { total: 0, alerts: 0, safe: 0, average_score: 0, max_score: 0 };
  return (
    <section className="cards">
      <div className="card"><div className="label">Total queries</div><div className="value">{s.total}</div></div>
      <div className="card safe"><div className="label">Safe</div><div className="value">{s.safe}</div></div>
      <div className="card alert"><div className="label">Alerts</div><div className="value">{s.alerts}</div></div>
      <div className="card"><div className="label">Avg score</div><div className="value">{s.average_score.toFixed(2)}</div></div>
      <div className="card"><div className="label">Max score</div><div className="value">{s.max_score.toFixed(2)}</div></div>
      <div className="card"><div className="label">Threshold</div><div className="value">{threshold.toFixed(2)}</div></div>
    </section>
  );
}
