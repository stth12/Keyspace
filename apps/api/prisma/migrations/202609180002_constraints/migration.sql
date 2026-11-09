ALTER TABLE users ADD CONSTRAINT login_ascii CHECK (login ~ '^[a-z0-9][a-z0-9_]{2,31}$');
ALTER TABLE users ADD CONSTRAINT auth_version_positive CHECK ("authVersion">0);
ALTER TABLE products ADD CONSTRAINT offline_grace_bounds CHECK ("offlineGrace" BETWEEN 60 AND 604800);
ALTER TABLE licenses ADD CONSTRAINT key_hash_length CHECK (octet_length("keyHash")=32);
ALTER TABLE licenses ADD CONSTRAINT term_shape CHECK (
 ("isLifetime" AND "durationSeconds" IS NULL AND "expiresAt" IS NULL) OR
 (NOT "isLifetime" AND "durationSeconds" BETWEEN 1 AND 315360000 AND (("activatedAt" IS NULL AND "expiresAt" IS NULL) OR ("activatedAt" IS NOT NULL AND "expiresAt">"activatedAt"))));
ALTER TABLE licenses ADD CONSTRAINT license_shape CHECK (
 (status<>'NOT_ACTIVATED' OR "activatedAt" IS NULL) AND
 (status NOT IN ('ACTIVE','EXPIRED') OR "activatedAt" IS NOT NULL) AND
 (status<>'EXPIRED' OR NOT "isLifetime") AND
 ((status='REVOKED')=("revokedAt" IS NOT NULL)) AND
 ((status='BLOCKED')=("blockedAt" IS NOT NULL)) AND
 ("maxDevices" IS NULL OR "maxDevices">0) AND "activationCount">=0 AND version>0);
ALTER TABLE license_entitlements ADD CONSTRAINT entitlement_bounds CHECK (remaining>=0 AND ("maxDevices" IS NULL OR "maxDevices">0));
ALTER TABLE refresh_tokens ADD CONSTRAINT refresh_kind CHECK (("webSessionId" IS NULL) <> ("appSessionId" IS NULL));
ALTER TABLE refresh_tokens ADD CONSTRAINT refresh_hash_length CHECK (octet_length("tokenHash")=32);
ALTER TABLE license_activations ADD CONSTRAINT seen_order CHECK ("lastSeenAt">="firstSeenAt");
ALTER TABLE token_issuances ADD CONSTRAINT issuance_license_fk FOREIGN KEY ("licenseId") REFERENCES licenses(id);
ALTER TABLE token_issuances ADD CONSTRAINT issuance_session_fk FOREIGN KEY ("sessionId") REFERENCES application_sessions(id);
ALTER TABLE token_issuances ADD CONSTRAINT issuance_signer_fk FOREIGN KEY ("keyId") REFERENCES signing_keys(id);
ALTER TABLE audit_logs ADD CONSTRAINT audit_actor_fk FOREIGN KEY ("actorUserId") REFERENCES users(id);
ALTER TABLE outbox_events ADD CONSTRAINT outbox_audit_fk FOREIGN KEY ("auditId") REFERENCES audit_logs(id);
CREATE UNIQUE INDEX one_active_signer ON signing_keys(purpose) WHERE status='ACTIVE';
CREATE INDEX active_license_expiry ON licenses("expiresAt") WHERE status='ACTIVE';
CREATE INDEX active_devices ON license_activations("licenseId") WHERE "revokedAt" IS NULL;
CREATE FUNCTION check_license_transition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.status=NEW.status THEN RETURN NEW; END IF;
 IF (OLD.status='NOT_ACTIVATED' AND NEW.status IN ('ACTIVE','BLOCKED','REVOKED')) OR
    (OLD.status='ACTIVE' AND NEW.status IN ('EXPIRED','BLOCKED','REVOKED')) OR
    (OLD.status='BLOCKED' AND NEW.status IN ('ACTIVE','NOT_ACTIVATED','EXPIRED','REVOKED')) OR
    (OLD.status='EXPIRED' AND NEW.status IN ('ACTIVE','REVOKED')) THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'invalid license transition';
END $$;
CREATE TRIGGER license_transition BEFORE UPDATE ON licenses FOR EACH ROW EXECUTE FUNCTION check_license_transition();
CREATE FUNCTION check_refresh_parent() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE parent refresh_tokens;
BEGIN
 IF NEW."parentId" IS NOT NULL THEN
   SELECT * INTO STRICT parent FROM refresh_tokens WHERE id=NEW."parentId";
   IF parent."webSessionId" IS DISTINCT FROM NEW."webSessionId" OR parent."appSessionId" IS DISTINCT FROM NEW."appSessionId" OR parent."consumedAt" IS NULL THEN
     RAISE EXCEPTION 'invalid refresh chain';
   END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER refresh_parent BEFORE INSERT ON refresh_tokens FOR EACH ROW EXECUTE FUNCTION check_refresh_parent();
