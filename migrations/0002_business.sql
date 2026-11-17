CREATE TABLE IF NOT EXISTS rate_limits (key TEXT NOT NULL,bucket INTEGER NOT NULL,count INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(key,bucket));
CREATE TABLE IF NOT EXISTS business_applications (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
 company_name TEXT NOT NULL,
 business_registration_number TEXT NOT NULL,
 representative_name TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
 submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_business_status ON business_applications(status);
