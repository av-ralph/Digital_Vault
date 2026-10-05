import { isIP } from "node:net";

export type LoginLocation = {
  city: string | null;
  region: string | null;
  country: string | null;
  countryCode: string | null;
  latitude: number | null;
  longitude: number | null;
  source: "Netlify IP geolocation";
  accuracy: "approximate";
};

function text(value: unknown, limit = 80) {
  return typeof value === "string"
    ? value
        .replace(/[\x00-\x1f\x7f]/g, "")
        .trim()
        .slice(0, limit) || null
    : null;
}

export function publicIp(value: string) {
  const ip = value.toLowerCase().replace(/^::ffff:/, "");
  if (isIP(ip) === 4) {
    const [a, b] = ip.split(".").map(Number);
    return !(
      a === 0 ||
      a === 10 ||
      a === 127 ||
      a >= 224 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  return (
    isIP(ip) === 6 &&
    ip !== "::" &&
    ip !== "::1" &&
    !/^(fc|fd|fe[89ab]|ff|2001:db8:)/.test(ip)
  );
}

// Only the function's trusted platform context supplies this input. Never read
// location fields from request bodies or browser-controlled forwarded headers.
export function locationFromGeo(
  value: unknown,
  ip: string,
): LoginLocation | null {
  return publicIp(ip) ? normalizeGeo(value) : null;
}

function normalizeGeo(value: unknown): LoginLocation | null {
  if (!value || typeof value !== "object") return null;
  const geo = value as Record<string, unknown>;
  const country =
    geo.country && typeof geo.country === "object"
      ? (geo.country as Record<string, unknown>)
      : {};
  const subdivision =
    geo.subdivision && typeof geo.subdivision === "object"
      ? (geo.subdivision as Record<string, unknown>)
      : {};
  const city = text(geo.city),
    region = text(subdivision.name),
    countryName = text(country.name);
  const code = text(country.code, 2)?.toUpperCase();
  const countryCode = code && /^[A-Z]{2}$/.test(code) ? code : null;
  const coordinate = (v: unknown, bound: number) => {
    const n =
      typeof v === "number"
        ? v
        : typeof v === "string" && v.trim()
          ? Number(v)
          : NaN;
    return Number.isFinite(n) && Math.abs(n) <= bound
      ? Math.round(n * 100) / 100
      : null;
  };
  let latitude = coordinate(geo.latitude, 90),
    longitude = coordinate(geo.longitude, 180);
  if (latitude === null || longitude === null) {
    latitude = null;
    longitude = null;
  }
  if (!city && !region && !countryName && !countryCode && latitude === null)
    return null;
  return {
    city,
    region,
    country: countryName,
    countryCode,
    latitude,
    longitude,
    source: "Netlify IP geolocation",
    accuracy: "approximate",
  };
}

export function storedLocation(value: unknown): LoginLocation | null {
  if (typeof value !== "string") return null;
  try {
    const raw = JSON.parse(value);
    return normalizeGeo({
      city: raw.city,
      subdivision: { name: raw.region },
      country: { name: raw.country, code: raw.countryCode },
      latitude: raw.latitude,
      longitude: raw.longitude,
    });
  } catch {
    return null;
  }
}
