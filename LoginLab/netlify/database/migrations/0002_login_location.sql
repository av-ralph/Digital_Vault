-- Metadata comes only from trusted Netlify request context. Existing events
-- remain NULL; no historical locations or demonstration activity are fabricated.
ALTER TABLE audit ADD COLUMN location TEXT;
