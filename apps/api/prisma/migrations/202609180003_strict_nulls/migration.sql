ALTER TABLE licenses DROP CONSTRAINT term_shape;
ALTER TABLE licenses ADD CONSTRAINT term_shape CHECK (
 ("isLifetime" AND "durationSeconds" IS NULL AND "expiresAt" IS NULL) OR
 (NOT "isLifetime" AND "durationSeconds" IS NOT NULL AND "durationSeconds" BETWEEN 1 AND 315360000 AND
 (("activatedAt" IS NULL AND "expiresAt" IS NULL) OR
 ("activatedAt" IS NOT NULL AND "expiresAt" IS NOT NULL AND "expiresAt">"activatedAt"))));
ALTER TABLE web_sessions ADD CONSTRAINT csrf_hash_length CHECK (octet_length("csrfHash")=32);
ALTER TABLE signing_keys ADD CONSTRAINT signing_bounds CHECK (purpose IN ('application-session','offline-license') AND status IN ('ACTIVE','VERIFY_ONLY','REVOKED') AND "verifyUntil">"notBefore");
