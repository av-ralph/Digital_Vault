import { useState } from "react";

export type AuditLocation = {
  city: string | null;
  region: string | null;
  country: string | null;
  countryCode: string | null;
  latitude: number | null;
  longitude: number | null;
  source: string;
  accuracy: "approximate";
};

export const locationName = (location: AuditLocation) =>
  [
    ...new Set(
      [
        location.city,
        location.region,
        location.country || location.countryCode,
      ].filter(Boolean),
    ),
  ].join(", ") || "Name unavailable";

export default function LoginLocation({
  location,
  ip,
}: {
  location: AuditLocation | null;
  ip: string;
}) {
  const [showMap, setShowMap] = useState(false);
  const local =
    /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|::1$|::ffff:127\.|f[cd]|fe[89ab])/i.test(
      ip,
    );
  if (!location)
    return (
      <section className="location-panel">
        <h3>Login location</h3>
        <p className="location-empty">
          {local
            ? "Location unavailable for local or private IP addresses."
            : "Location not recorded for this request."}
        </p>
        <p className="caption">
          New hosted login attempts include the location when the provider can
          resolve it. Older records are not backfilled.
        </p>
      </section>
    );
  const name = locationName(location),
    lat = location.latitude,
    lon = location.longitude;
  const coordinates =
    typeof lat === "number" &&
    typeof lon === "number" &&
    Number.isFinite(lat) &&
    Number.isFinite(lon) &&
    Math.abs(lat) <= 85 &&
    Math.abs(lon) <= 180;
  const bbox = coordinates
    ? [
        Math.max(-180, lon - 0.15),
        Math.max(-85, lat - 0.12),
        Math.min(180, lon + 0.15),
        Math.min(85, lat + 0.12),
      ].join(",")
    : "";
  const params = new URLSearchParams({
    bbox,
    layer: "mapnik",
    marker: `${lat},${lon}`,
  });
  return (
    <section className="location-panel" aria-label="Login location">
      <div className="location-heading">
        <h3>IP-based location estimate</h3>
        <span className="badge">IP estimate</span>
      </div>
      <p className="location-name">{name}</p>
      <p className="location-explanation">
        This is an estimate of the network’s location, not the person’s exact
        address. VPNs, mobile networks, and routing can place it elsewhere.
      </p>
      {coordinates ? (
        <>
          <div className="location-actions">
            <button
              type="button"
              className="secondary"
              aria-expanded={showMap}
              onClick={() => setShowMap(!showMap)}
            >
              {showMap ? "Hide map" : "Show map"}
            </button>
            <a
              href={`https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=10/${lat}/${lon}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              Open in OpenStreetMap
            </a>
          </div>
          {showMap && (
            <div className="map-container">
              <iframe
                title={`Approximate login location: ${name}`}
                src={`https://www.openstreetmap.org/export/embed.html?${params}`}
                loading="lazy"
                referrerPolicy="no-referrer"
              />
              <p className="caption">
                The marker shows the estimated area. If the map is unavailable,
                use the OpenStreetMap link above. ©{" "}
                <a
                  href="https://www.openstreetmap.org/copyright"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  OpenStreetMap contributors
                </a>
              </p>
            </div>
          )}
        </>
      ) : (
        <p className="location-empty">
          Map unavailable: no usable coordinates were provided.
        </p>
      )}
      <p className="caption">
        Location source: {location.source}. Map: OpenStreetMap.
      </p>
    </section>
  );
}
