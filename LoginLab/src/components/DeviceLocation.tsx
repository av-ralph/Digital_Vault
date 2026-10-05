import { useEffect, useRef, useState } from "react";
export type BrowserLocation = {
  consent: true;
  latitude: number;
  longitude: number;
  accuracyMeters: number;
  collectedAt: number;
};
export function OptionalLocation({
  onChange,
  disabled,
}: {
  onChange: (value: BrowserLocation | null) => void;
  disabled: boolean;
}) {
  const [status, setStatus] = useState(""),
    [locating, setLocating] = useState(false),
    [shared, setShared] = useState(false);
  const generation = useRef(0);
  useEffect(
    () => () => {
      generation.current++;
    },
    [],
  );
  function clear() {
    generation.current++;
    setLocating(false);
    setShared(false);
    setStatus(
      "Device location removed. Sign-in will use the IP estimate only.",
    );
    onChange(null);
  }
  function share() {
    if (!window.isSecureContext || !navigator.geolocation) {
      setStatus(
        "Device location is unavailable in this browser. You can still sign in.",
      );
      return;
    }
    const token = ++generation.current;
    setLocating(true);
    setStatus("Waiting for location permission...");
    navigator.geolocation.getCurrentPosition(
      (position) => {
        if (token !== generation.current) return;
        const { latitude, longitude, accuracy } = position.coords;
        onChange({
          consent: true,
          latitude,
          longitude,
          accuracyMeters: accuracy,
          collectedAt: position.timestamp,
        });
        setLocating(false);
        setShared(true);
        setStatus(
          "Device location ready for this sign-in. Reported accuracy radius: " +
            Math.ceil(accuracy) +
            " metres.",
        );
      },
      (error) => {
        if (token !== generation.current) return;
        onChange(null);
        setLocating(false);
        setShared(false);
        setStatus(
          error.code === 1
            ? "Permission declined. You can sign in using the IP estimate only."
            : error.code === 3
              ? "Location request timed out. You can still sign in or try again."
              : "Your device could not provide a location. You can still sign in.",
        );
      },
      { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 },
    );
  }
  return (
    <section
      className="optional-location"
      aria-label="Optional device location"
    >
      <h3>Share device location (optional)</h3>
      <p>
        Choose this only if you want to include your device's position with this
        login attempt. Your browser will ask permission. Digital_Vault stores it
        with the login record; authorized administrators can view it until the
        record expires. You can sign in without sharing.
      </p>
      <button
        type="button"
        className="secondary"
        disabled={disabled || locating}
        onClick={share}
      >
        {locating
          ? "Requesting location..."
          : shared
            ? "Update device location"
            : "Share device location"}
      </button>
      {(shared || locating) && (
        <button
          type="button"
          className="secondary"
          disabled={disabled}
          onClick={clear}
        >
          {locating ? "Cancel location request" : "Remove location"}
        </button>
      )}
      <p className="caption" role="status">
        {status}
      </p>
    </section>
  );
}
export default function DeviceLocation({
  location,
}: {
  location: BrowserLocation | null;
}) {
  const [show, setShow] = useState(false);
  if (!location) return null;
  const lat = location.latitude,
    lon = location.longitude;
  const span = Math.max(
    0.001,
    Math.min(2, (location.accuracyMeters / 111000) * 2),
  );
  const lonSpan = span / Math.max(0.1, Math.cos((lat * Math.PI) / 180));
  const params = new URLSearchParams({
    bbox: [
      Math.max(-180, lon - lonSpan),
      Math.max(-85, lat - span),
      Math.min(180, lon + lonSpan),
      Math.min(85, lat + span),
    ].join(","),
    layer: "mapnik",
    marker: lat + "," + lon,
  });
  return (
    <section
      className="location-panel"
      aria-label="Browser-reported device location"
    >
      <div className="location-heading">
        <h3>Device location</h3>
        <span className="badge">Browser-reported</span>
      </div>
      <p className="location-name">
        Reported accuracy radius: {location.accuracyMeters.toLocaleString()}{" "}
        metres
      </p>
      <p>
        Latitude {lat.toFixed(6)}, longitude {lon.toFixed(6)} | Collected{" "}
        {new Date(location.collectedAt).toLocaleString()}
      </p>
      <p className="location-explanation">
        Shared by the user for this login attempt. This is a device estimate,
        which can be inaccurate or changed by the client. It is not verified
        proof of the person's exact location. The IP-based place name below
        describes the network, not this device position.
      </p>
      {Math.abs(lat) <= 85 ? (
        <>
          <p className="caption">
            Opening this map sends the device coordinates to OpenStreetMap.
          </p>
          <div className="location-actions">
            <button
              type="button"
              className="secondary"
              aria-expanded={show}
              onClick={() => setShow(!show)}
            >
              {show ? "Hide device map" : "Show device map"}
            </button>
            <a
              href={
                "https://www.openstreetmap.org/?mlat=" +
                lat +
                "&mlon=" +
                lon +
                "#map=16/" +
                lat +
                "/" +
                lon
              }
              target="_blank"
              rel="noopener noreferrer"
            >
              Open device map in OpenStreetMap
            </a>
          </div>
          {show && (
            <div className="map-container">
              <iframe
                title="Browser-reported device position"
                src={
                  "https://www.openstreetmap.org/export/embed.html?" + params
                }
                loading="lazy"
                referrerPolicy="no-referrer"
              />
              <p className="caption">
                The marker shows the reported position; the accuracy radius
                above describes its uncertainty. (c){" "}
                <a
                  href="https://www.openstreetmap.org/copyright"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  OpenStreetMap contributors
                </a>
                . If the map does not load, use the link above.
              </p>
            </div>
          )}
        </>
      ) : (
        <p>Map unavailable at this latitude.</p>
      )}
    </section>
  );
}
