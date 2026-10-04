process.env.NODE_ENV = "production";
// The built frontend shares the API origin. Production overrides the development-only default.
if (!process.env.TRUSTED_ORIGINS)
  process.env.TRUSTED_ORIGINS = `http://127.0.0.1:${process.env.PORT || 3001}`;
