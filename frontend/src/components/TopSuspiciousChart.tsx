import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { TopSuspicious } from "../types";

export function TopSuspiciousChart({ data }: { data: TopSuspicious[] }) {
  return (
    <div className="panel">
      <h2>Top suspicious domains</h2>
      {data.length === 0 ? (
        <div className="empty">No alerts yet</div>
      ) : (
        <ResponsiveContainer width="100%" height={Math.max(220, data.length * 28)}>
          <BarChart data={data} layout="vertical" margin={{ left: 60 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis type="number" fontSize={11} />
            <YAxis
              type="category"
              dataKey="query_name"
              fontSize={10}
              width={200}
              tick={{ fill: "#34495e" }}
            />
            <Tooltip />
            <Bar dataKey="count" fill="#c43d3d" name="Hits" />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
