-- Which user attributes a client's access tokens may carry (SPEC §8.2, `wd.attrs`).
--
-- The specification says "configurable per application", and this is on the client
-- instead. The reason is that an access token is issued to a *client*, and a client need
-- not correspond to an application at all — migration 000014 says so at length, and there
-- is no link between the two tables to read an allowlist through. The client is the thing
-- that actually receives the token, so it is the thing whose registration decides what the
-- token discloses. When applications and clients are related (M2), this can compose with
-- an application-level list rather than move.
--
-- Empty by default, and the default is the point: attributes are user data, and a client
-- that has not been granted any receives none. `wd.attrs` is a convenience that saves a
-- round trip to the decision API, not a channel for profile data.
ALTER TABLE oauth_client
    ADD COLUMN token_attributes text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN oauth_client.token_attributes IS
    'Allowlist of app_user.attributes keys this client''s access tokens may carry in wd.attrs (SPEC §8.2). Empty means none.';
