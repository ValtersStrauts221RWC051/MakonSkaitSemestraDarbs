import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { HourlyBucket } from "../types";

export function HourlyChart({ data }: { data: HourlyBucket[] }) {
  const formatted = data.map((d) => ({
    ...d,
    hour: d.hour ? d.hour.slice(11, 16) : "",
  }));
  return (
    <div className="panel">
      <h2>Hourly volume</h2>
      <ResponsiveContainer width="100%" height={240}>
        <BarChart data={formatted}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="hour" fontSize={11} />
          <YAxis fontSize={11} />
          <Tooltip />
          <Legend wrapperStyle={{ fontSize: 12 }} />
          <Bar dataKey="total" fill="#3b82a8" name="Total" />
          <Bar dataKey="alerts" fill="#c43d3d" name="Alerts" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
