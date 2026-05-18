import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { queryTypeLabel } from "../labels";
import type { QueryTypeCount } from "../types";

const SUSPICIOUS = new Set(["TXT", "NULL", "MX"]);

export function QueryTypeChart({ data }: { data: QueryTypeCount[] }) {
  const enriched = data.map((d) => ({ ...d, label: queryTypeLabel(d.query_type) }));
  return (
    <div className="panel">
      <h2>Query types</h2>
      {data.length === 0 ? (
        <div className="empty">No data</div>
      ) : (
        <ResponsiveContainer width="100%" height={240}>
          <PieChart>
            <Pie
              data={enriched}
              dataKey="count"
              nameKey="label"
              cx="50%"
              cy="50%"
              outerRadius={80}
              label={(e: { label: string }) => e.label}
              labelLine={false}
            >
              {enriched.map((d, i) => (
                <Cell key={i} fill={SUSPICIOUS.has(d.query_type) ? "#c43d3d" : "#3b82a8"} />
              ))}
            </Pie>
            <Tooltip />
            <Legend wrapperStyle={{ fontSize: 11 }} />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
