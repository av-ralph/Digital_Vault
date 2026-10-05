type Position = {
  coords: { latitude: number; longitude: number; accuracy: number };
  timestamp: number;
};
type Geo = {
  getCurrentPosition: (
    success: (position: Position) => void,
    error: (error: { code: number }) => void,
    options: {
      enableHighAccuracy: boolean;
      timeout: number;
      maximumAge: number;
    },
  ) => void;
};
type Options = {
  geo: Geo;
  ready: (position: Position) => void;
  failed: (code: number) => void;
  fallback: () => void;
  schedule?: (
    callback: () => void,
    ms: number,
  ) => ReturnType<typeof setTimeout>;
  cancelTimer?: (timer: ReturnType<typeof setTimeout>) => void;
};
export function requestDevicePosition({
  geo,
  ready,
  failed,
  fallback,
  schedule = setTimeout,
  cancelTimer = clearTimeout,
}: Options) {
  let ended = false,
    stage = 0,
    timer: ReturnType<typeof setTimeout> | undefined;
  const clear = () => {
    if (timer !== undefined) cancelTimer(timer);
    timer = undefined;
  };
  function attempt(high: boolean) {
    const current = ++stage;
    const active = () => !ended && current === stage;
    const error = (code: number) => {
      if (!active()) return;
      clear();
      if (high && code !== 1) {
        fallback();
        attempt(false);
      } else {
        ended = true;
        failed(code);
      }
    };
    timer = schedule(() => error(3), high ? 18000 : 22000);
    try {
      geo.getCurrentPosition(
        (position) => {
          if (!active()) return;
          const { latitude, longitude, accuracy } = position.coords;
          if (
            !Number.isFinite(latitude) ||
            Math.abs(latitude) > 90 ||
            !Number.isFinite(longitude) ||
            Math.abs(longitude) > 180 ||
            !Number.isFinite(accuracy) ||
            accuracy < 0 ||
            !Number.isFinite(position.timestamp) ||
            Date.now() - position.timestamp > 300000 ||
            position.timestamp > Date.now() + 30000
          ) {
            error(2);
            return;
          }
          ended = true;
          clear();
          ready(position);
        },
        (errorValue) => error(errorValue.code),
        {
          enableHighAccuracy: high,
          timeout: high ? 12000 : 20000,
          maximumAge: 0,
        },
      );
    } catch {
      error(2);
    }
  }
  attempt(true);
  return () => {
    ended = true;
    stage++;
    clear();
  };
}
