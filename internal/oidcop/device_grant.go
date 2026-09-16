package oidcop

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"

	"github.com/warden-project/warden/internal/authn"
)

// The device authorization grant, at the token endpoint (RFC 8628 §3.4, §3.5).
//
// Hand-written rather than composed, because fosite v0.49 has no RFC 8628 handler — not
// a disabled one, none at all; the module contains no reference to a device code. What
// fosite does provide is the extension point: a TokenEndpointHandler is consulted for
// every token request, so the grant plugs into the same pipeline as the others and
// inherits client authentication, error rendering and the token strategies rather than
// reimplementing them.

// The grant type itself is GrantDeviceCode, declared alongside the others in client.go
// so that the registry and the handler cannot disagree about its name.

// The three errors RFC 8628 §3.5 defines for polling, which are not in fosite because
// the grant is not.
//
// They are ordinary token-endpoint errors as far as the wire is concerned — a 400 with
// an `error` field — and the device's client library switches on exactly these names to
// decide whether to keep waiting, wait longer, or give up. Getting one of them wrong
// turns a working device into one that polls forever.
var (
	// ErrAuthorizationPending means nobody has answered yet. The device keeps polling.
	ErrAuthorizationPending = &fosite.RFC6749Error{
		ErrorField:       "authorization_pending",
		DescriptionField: "The authorization request is still pending; the user has not yet approved it.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrSlowDown means the device is polling faster than it was told to. §3.5 requires
	// the client to add five seconds to its interval and carry on.
	ErrSlowDown = &fosite.RFC6749Error{
		ErrorField:       "slow_down",
		DescriptionField: "The device is polling too frequently; increase the interval by five seconds.",
		CodeField:        http.StatusBadRequest,
	}

	// ErrExpiredDeviceToken means the device waited too long. Distinct from
	// invalid_grant, so a device can say "the code on the screen has expired" rather
	// than "something went wrong".
	ErrExpiredDeviceToken = &fosite.RFC6749Error{
		ErrorField:       "expired_token",
		DescriptionField: "The device code has expired; start the flow again.",
		CodeField:        http.StatusBadRequest,
	}
)

// deviceGrantHandler serves grant_type=urn:ietf:params:oauth:grant-type:device_code.
type deviceGrantHandler struct {
	storage  *Storage
	sessions *authn.Sessions
	strategy oauth2.CoreStrategy
	idTokens openid.OpenIDConnectTokenStrategy
	config   *fosite.Config
	issuer   string
	log      *slog.Logger
}

var _ fosite.TokenEndpointHandler = (*deviceGrantHandler)(nil)

// CanHandleTokenEndpointRequest reports whether this is a device-code exchange.
func (h *deviceGrantHandler) CanHandleTokenEndpointRequest(_ context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(GrantDeviceCode)
}

// CanSkipClientAuth is false.
//
// A device client is usually public and authenticates by sending its client_id, which
// fosite accepts — but "public" is not "anonymous". Allowing the request through without
// a client at all would mean a stolen device code could be redeemed by anybody, and the
// check that the code belongs to *this* client would have nothing to compare against.
func (h *deviceGrantHandler) CanSkipClientAuth(_ context.Context, _ fosite.AccessRequester) bool {
	return false
}

// HandleTokenEndpointRequest answers the device's poll.
//
// Every branch here is one of RFC 8628 §3.5's answers, and the differences between them
// matter to a device that has nothing but this response to act on: keep waiting, wait
// longer, the person said no, the code expired, start again.
func (h *deviceGrantHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	if !h.CanHandleTokenEndpointRequest(ctx, requester) {
		return fosite.ErrUnknownRequest
	}

	client := requester.GetClient()
	if !client.GetGrantTypes().Has(GrantDeviceCode) {
		return fosite.ErrUnauthorizedClient.WithHint(
			"The OAuth 2.0 Client is not allowed to use the device authorization grant.")
	}

	tenantID, ok := TenantFrom(ctx)
	if !ok {
		return fosite.ErrServerError.WithDebug("a device token request reached the grant with no tenant scope")
	}

	deviceCode := requester.GetRequestForm().Get("device_code")
	if deviceCode == "" {
		return fosite.ErrInvalidRequest.WithHint("Request parameter 'device_code' is missing.")
	}

	record, err := h.storage.pollDevice(ctx, tenantID, deviceCode)
	if errors.Is(err, ErrNoSuchDeviceCode) {
		return fosite.ErrInvalidGrant.WithHint("The device code is unknown or has already been used.")
	}
	if err != nil {
		return fosite.ErrServerError.WithWrap(err).WithDebug(err.Error())
	}

	if record.ClientID != client.GetID() {
		// Answered as an unknown code rather than as "not yours": the two must look the
		// same, or a client could confirm that a code it does not own exists.
		h.log.Warn("a client polled with a device code issued to another client",
			"client_id", client.GetID(), "tenant_id", tenantID)
		return fosite.ErrInvalidGrant.WithHint("The device code is unknown or has already been used.")
	}

	now := time.Now().UTC()
	if record.Expired(now) {
		return ErrExpiredDeviceToken
	}

	switch record.Status {
	case DeviceStatusDenied:
		return fosite.ErrAccessDenied.WithHint("The user declined the request.")
	case DeviceStatusRedeemed:
		// A device code is single use. A second presentation is either a retry after a
		// response the device lost, or somebody else replaying it; both get the same
		// answer, and the tokens from the first exchange are unaffected.
		return fosite.ErrInvalidGrant.WithHint("The device code is unknown or has already been used.")
	case DeviceStatusPending:
		if record.LastPolledAt != nil && now.Sub(*record.LastPolledAt) < record.Interval {
			return ErrSlowDown
		}
		return ErrAuthorizationPending
	case DeviceStatusApproved:
		// Below.
	default:
		return fosite.ErrServerError.WithDebugf("unknown device authorization status %q", record.Status)
	}

	// Approved — but by a session that may since have ended. Checking it here is what
	// makes a logout reach a device that was approved and never polled again: without
	// it, signing out would leave a television able to collect its tokens afterwards.
	if h.sessions == nil {
		return fosite.ErrServerError.WithDebug("the device grant needs the session store")
	}
	session, err := h.sessions.Validate(ctx, record.SessionID)
	if err != nil {
		h.log.Info("a device poll named an approval whose session has ended",
			"tenant_id", tenantID, "session_id", record.SessionID)
		return fosite.ErrInvalidGrant.WithHint(
			"The session that approved this device has ended. Start the flow again.")
	}
	if session.TenantID != tenantID || session.UserID != record.Subject {
		// Belt and braces on a boundary that already holds: the row was read under
		// row-level security for this tenant. Two guards is the right number for the
		// one SPEC §17.1 names.
		return fosite.ErrInvalidGrant.WithHint("The device code is unknown or has already been used.")
	}

	granted := record.GrantedScope
	wardenSession := NewSession(h.issuer, tenantID, session.ID, session.UserID,
		session.AuthTime, session.AMR)
	wardenSession.SetExpiresAt(fosite.AccessToken, now.Add(h.config.GetAccessTokenLifespan(ctx)))
	if fosite.Arguments(granted).HasOneOf(h.config.GetRefreshTokenScopes(ctx)...) {
		wardenSession.SetExpiresAt(fosite.RefreshToken, now.Add(h.config.GetRefreshTokenLifespan(ctx)))
	}
	requester.SetSession(wardenSession)

	// The scopes were settled when the person approved. Set as requested as well as
	// granted so that the stored row, and anything introspecting it later, describes one
	// coherent request rather than a grant of things nobody asked for.
	requester.SetRequestedScopes(granted)
	for _, scope := range granted {
		requester.GrantScope(scope)
	}
	requester.SetRequestedAudience(record.GrantedAudience)
	for _, audience := range record.GrantedAudience {
		requester.GrantAudience(audience)
	}
	return nil
}

// canIssueRefreshToken applies the same two conditions fosite's authorization code
// handler does.
//
// The second is the one a live run caught: a client registered for the device grant alone
// was handed a refresh token it could never use, because fosite's refresh handler requires
// the client to hold the refresh_token grant. A device developer would have built a
// refresh loop around a credential that answers unauthorized_client for ever.
func (h *deviceGrantHandler) canIssueRefreshToken(ctx context.Context, requester fosite.AccessRequester) bool {
	scopes := h.config.GetRefreshTokenScopes(ctx)
	if len(scopes) > 0 && !requester.GetGrantedScopes().HasOneOf(scopes...) {
		return false
	}
	return requester.GetClient().GetGrantTypes().Has(GrantRefreshToken)
}

// PopulateTokenEndpointResponse issues the tokens for an approved device.
func (h *deviceGrantHandler) PopulateTokenEndpointResponse(
	ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder,
) error {
	if !h.CanHandleTokenEndpointRequest(ctx, requester) {
		return fosite.ErrUnknownRequest
	}
	tenantID, ok := TenantFrom(ctx)
	if !ok {
		return fosite.ErrServerError.WithDebug("a device token request reached the response with no tenant scope")
	}
	deviceCode := requester.GetRequestForm().Get("device_code")

	// Spent before anything is issued, and in one statement whose WHERE clause carries
	// the rule: two polls arriving together must not both produce tokens. The one that
	// changes no rows loses, and is told the code is unknown — which by then it is.
	if err := h.storage.redeemDevice(ctx, tenantID, deviceCode); err != nil {
		if errors.Is(err, ErrNoSuchDeviceCode) {
			return fosite.ErrInvalidGrant.WithHint("The device code is unknown or has already been used.")
		}
		return fosite.ErrServerError.WithWrap(err).WithDebug(err.Error())
	}

	// Sanitized, so the device code itself is not copied into the stored request form.
	// A row that carried it would be a second place the credential lives.
	stored := requester.Sanitize(nil)

	accessToken, accessSignature, err := h.strategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return fosite.ErrServerError.WithWrap(err).WithDebug(err.Error())
	}
	if err := h.storage.CreateAccessTokenSession(ctx, accessSignature, stored); err != nil {
		return fosite.ErrServerError.WithWrap(err).WithDebug(err.Error())
	}

	responder.SetAccessToken(accessToken)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(time.Until(requester.GetSession().GetExpiresAt(fosite.AccessToken)))
	responder.SetScopes(requester.GetGrantedScopes())

	if h.canIssueRefreshToken(ctx, requester) {
		refreshToken, refreshSignature, refreshErr := h.strategy.GenerateRefreshToken(ctx, requester)
		if refreshErr != nil {
			return fosite.ErrServerError.WithWrap(refreshErr).WithDebug(refreshErr.Error())
		}
		// Through the same storage the authorization code flow uses, so a device's
		// refresh token joins a family, rotates, and is subject to M1-5's reuse
		// detection exactly like everybody else's.
		if createErr := h.storage.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, stored); createErr != nil {
			return fosite.ErrServerError.WithWrap(createErr).WithDebug(createErr.Error())
		}
		responder.SetExtra("refresh_token", refreshToken)
	}

	if requester.GetGrantedScopes().Has("openid") {
		idToken, idErr := h.idTokens.GenerateIDToken(ctx, h.config.GetIDTokenLifespan(ctx), requester)
		if idErr != nil {
			return fosite.ErrServerError.WithWrap(idErr).WithDebug(idErr.Error())
		}
		responder.SetExtra("id_token", idToken)
	}
	return nil
}
