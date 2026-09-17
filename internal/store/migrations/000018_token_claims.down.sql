ALTER TABLE oauth_client DROP CONSTRAINT IF EXISTS oauth_client_token_claims_valid;
ALTER TABLE oauth_client DROP COLUMN IF EXISTS token_claims;
