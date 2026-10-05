import test from "node:test";
import assert from "node:assert/strict";
import { requestDevicePosition } from "../src/devicePosition.js";
function fixture() {
  const calls: any[] = [];
  const timers = new Map<number, () => void>();
  let next = 0,
    ready: any = null,
    failed = 0,
    fallback = 0;
  const cancel = requestDevicePosition({
    geo: {
      getCurrentPosition: (success, error, options) => {
        calls.push({ success, error, options });
      },
    },
    ready: (position) => {
      ready = position;
    },
    failed: (code) => {
      failed = code;
    },
    fallback: () => {
      fallback++;
    },
    schedule: (callback) => {
      timers.set(++next, callback);
      return next as any;
    },
    cancelTimer: (id) => {
      timers.delete(id as any);
    },
  });
  return {
    calls,
    timers,
    cancel,
    get ready() {
      return ready;
    },
    get failed() {
      return failed;
    },
    get fallback() {
      return fallback;
    },
  };
}
const position = () => ({
  coords: { latitude: 14.6, longitude: 120.98, accuracy: 25 },
  timestamp: Date.now(),
});
test("device location success clears timeout; permission denial never retries", () => {
  const f = fixture();
  f.calls[0].success(position());
  assert.equal(f.ready.coords.accuracy, 25);
  assert.equal(f.timers.size, 0);
  const denied = fixture();
  denied.calls[0].error({ code: 1 });
  assert.equal(denied.failed, 1);
  assert.equal(denied.calls.length, 1);
  assert.equal(denied.timers.size, 0);
});
test("high accuracy failures retry standard positioning and ignore stale callbacks", () => {
  const f = fixture();
  f.calls[0].error({ code: 3 });
  assert.equal(f.fallback, 1);
  assert.equal(f.calls[1].options.enableHighAccuracy, false);
  f.calls[0].success(position());
  assert.equal(f.ready, null);
  f.calls[1].success(position());
  assert.equal((f.ready as any).coords.latitude, 14.6);
  assert.equal(f.timers.size, 0);
});
test("unresponsive provider terminates after both watchdogs; cancellation discards late positions", () => {
  const f = fixture();
  [...f.timers.values()][0]();
  assert.equal(f.calls.length, 2);
  [...f.timers.values()][0]();
  assert.equal(f.failed, 3);
  assert.equal(f.timers.size, 0);
  const cancelled = fixture();
  cancelled.cancel();
  cancelled.calls[0].success(position());
  assert.equal(cancelled.ready, null);
  assert.equal(cancelled.failed, 0);
  assert.equal(cancelled.timers.size, 0);
});
test("invalid or stale provider positions cannot be submitted", () => {
  const f = fixture();
  f.calls[0].success({ ...position(), timestamp: Date.now() - 600000 });
  assert.equal(f.calls.length, 2);
  f.calls[1].success({
    coords: { latitude: NaN, longitude: 120, accuracy: 25 },
    timestamp: Date.now(),
  });
  assert.equal(f.failed, 2);
  assert.equal(f.ready, null);
});

