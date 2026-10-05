import test from "node:test";
import assert from "node:assert/strict";
import { locationFromGeo, publicIp, storedLocation } from "./location.js";
test("private and loopback addresses cannot produce location estimates", () => {
  for (const ip of [
    "127.0.0.1",
    "::1",
    "::ffff:127.0.0.1",
    "10.0.0.1",
    "192.168.1.2",
    "172.16.2.1",
    "100.64.0.1",
    "fd00::1",
    "fe80::1",
    "unknown",
  ]) {
    assert.equal(publicIp(ip), false);
    assert.equal(locationFromGeo({ city: "Manila" }, ip), null);
  }
  assert.equal(publicIp("8.8.8.8"), true);
  assert.equal(publicIp("2606:4700:4700::1111"), true);
});
test("trusted location is bounded, safely normalized and rounded with zero coordinates preserved", () => {
  const location = locationFromGeo(
    {
      city: "  Manila\u0000 ",
      subdivision: { name: "x".repeat(100) },
      country: { code: "ph", name: "Philippines" },
      latitude: 0,
      longitude: "120.98422",
      password: "excluded",
    },
    "8.8.8.8",
  )!;
  assert.equal(location.city, "Manila");
  assert.equal(location.region!.length, 80);
  assert.equal(location.countryCode, "PH");
  assert.equal(location.latitude, 0);
  assert.equal(location.longitude, 120.98);
  assert.equal("password" in location, false);
  assert.equal(location.source, "Netlify IP geolocation");
  assert.deepEqual(storedLocation(JSON.stringify(location)), location);
});
test("missing, malformed and invalid coordinates produce honest unavailable states", () => {
  for (const value of [null, undefined, "", "{", "null", "{}"])
    assert.equal(storedLocation(value), null);
  assert.equal(
    locationFromGeo({ latitude: 91, longitude: 0 }, "8.8.8.8"),
    null,
  );
  const location = locationFromGeo(
    { city: "Manila", latitude: 14, longitude: 181 },
    "8.8.8.8",
  )!;
  assert.equal(location.latitude, null);
  assert.equal(location.longitude, null);
});
