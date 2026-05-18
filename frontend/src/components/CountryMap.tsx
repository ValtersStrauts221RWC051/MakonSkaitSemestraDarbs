import { useMemo } from "react";
import { ComposableMap, Geographies, Geography } from "react-simple-maps";
import type { CountryStat } from "../types";

const GEO_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

interface Props {
  data: CountryStat[];
}

interface Bucket {
  total: number;
  alerts: number;
  country: string;
}

export function CountryMap({ data }: Props) {
  const map = useMemo(() => {
    const m: Record<string, Bucket> = {};
    let maxTotal = 0;
    for (const c of data) {
      if (!c.country_code || c.country_code === "??") continue;
      m[c.country_code.toUpperCase()] = {
        total: c.total,
        alerts: c.alerts,
        country: c.country,
      };
      if (c.total > maxTotal) maxTotal = c.total;
    }
    return { m, maxTotal };
  }, [data]);

  const unknownTotal = data
    .filter((c) => !c.country_code || c.country_code === "??")
    .reduce((sum, c) => sum + c.total, 0);

  return (
    <div className="panel">
      <h2>Traffic origin by country</h2>
      <div style={{ display: "flex", gap: 24, alignItems: "stretch" }}>
        <div style={{ flex: 1 }}>
          <ComposableMap
            projectionConfig={{ scale: 130 }}
            style={{ width: "100%", height: 320 }}
          >
            <Geographies geography={GEO_URL}>
              {({ geographies }) =>
                geographies.map((geo) => {
                  const iso = geo.properties.iso_a2 ?? geo.id;
                  const bucket = map.m[iso?.toUpperCase()];
                  const intensity = bucket ? bucket.total / Math.max(1, map.maxTotal) : 0;
                  const alertRatio = bucket && bucket.total > 0 ? bucket.alerts / bucket.total : 0;

                  let fill = "#e6ecf2";
                  if (bucket) {
                    if (alertRatio >= 0.5) {
                      fill = `rgba(196, 61, 61, ${0.25 + intensity * 0.75})`;
                    } else if (alertRatio >= 0.1) {
                      fill = `rgba(196, 130, 61, ${0.25 + intensity * 0.75})`;
                    } else {
                      fill = `rgba(59, 130, 168, ${0.25 + intensity * 0.75})`;
                    }
                  }

                  const tooltip = bucket
                    ? `${bucket.country}: ${bucket.total} queries (${bucket.alerts} alerts, ${(alertRatio * 100).toFixed(0)}%)`
                    : geo.properties.name;

                  return (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill={fill}
                      stroke="#fff"
                      strokeWidth={0.4}
                      style={{
                        default: { outline: "none" },
                        hover: { fill: "#16324f", outline: "none", cursor: "pointer" },
                        pressed: { outline: "none" },
                      }}
                    >
                      <title>{tooltip}</title>
                    </Geography>
                  );
                })
              }
            </Geographies>
          </ComposableMap>
        </div>

        <div style={{ width: 220, fontSize: 12 }}>
          <h3 style={{ fontSize: 13, marginTop: 0 }}>Legend</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <Legend color="rgba(59, 130, 168, 0.7)" text="Benign traffic" />
            <Legend color="rgba(196, 130, 61, 0.7)" text="Some alerts (≥10%)" />
            <Legend color="rgba(196, 61, 61, 0.7)" text="Mostly malicious (≥50%)" />
            <Legend color="#e6ecf2" text="No data" />
          </div>

          <h3 style={{ fontSize: 13, marginTop: 14 }}>Top countries</h3>
          {data.slice(0, 5).map((c) => (
            <div key={c.country_code} style={{ display: "flex", justifyContent: "space-between", padding: "2px 0" }}>
              <span>{c.country_code === "??" ? "Unknown" : c.country}</span>
              <span>
                <strong>{c.total}</strong>
                {c.alerts > 0 && <span style={{ color: "#c43d3d" }}> ({c.alerts}!)</span>}
              </span>
            </div>
          ))}
          {unknownTotal > 0 && (
            <div style={{ marginTop: 8, color: "#6c7a89", fontSize: 11 }}>
              {unknownTotal} queries unresolved
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Legend({ color, text }: { color: string; text: string }) {
  return (
    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
      <span style={{ width: 18, height: 12, background: color, borderRadius: 2, display: "inline-block" }} />
      <span>{text}</span>
    </div>
  );
}
