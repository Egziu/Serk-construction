-- DEVELOPMENT ONLY — mounted by docker-compose.dev.yml, never by the
-- production profile. Published, well-known passwords for local logins.
ALTER ROLE serk_health PASSWORD 'dev-only-health-password';
ALTER ROLE serk_timer  PASSWORD 'dev-only-timer-password';
ALTER ROLE serk_ratelimit PASSWORD 'dev-only-ratelimit-password';
