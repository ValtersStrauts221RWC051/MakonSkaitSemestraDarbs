import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ParentDist } from "../types";

export function TopDomainsChart({ data }: { data: ParentDist[] }) {
  return (
    <div className="panel">
      <h2>Top queried domains</h2>
      {data.length === 0 ? (
        <div className="empty">No data</div>
      ) : (
        <ResponsiveContainer width="100%" height={Math.max(220, data.length * 28)}>
          <BarChart data={data} layout="vertical" margin={{ left: 60 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis type="number" fontSize={11} />
            <YAxis
              type="category"
              dataKey="parent_domain"
              fontSize={11}
              width={180}
              tick={{ fill: "#34495e" }}
            />
            <Tooltip />
            <Bar dataKey="count" fill="#3b82a8" name="Queries" />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
