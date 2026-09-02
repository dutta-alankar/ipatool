package appstore

import (
	"encoding/json"
	"errors"
	"fmt"
	gohttp "net/http"
	"strconv"
	"strings"
	"time"

	"github.com/majd/ipatool/v2/pkg/http"
)

var (
	ErrAuthCodeRequired = errors.New("auth code is required")

	// errTransientAuthResponse marks responses Apple's auth endpoints return
	// intermittently since the August 2026 attestation rollout — empty 403/204
	// bodies, HTML 404/500 pages, redirects without a Location header. The
	// same request often succeeds when retried or sent to another endpoint.
	errTransientAuthResponse = errors.New("apple auth endpoint is unavailable")
)

const (
	// The bag's authenticateAccount URL currently points at the legacy
	// MZFinance authenticate endpoint, which Apple rejects outright with an
	// empty 403. The native endpoint still answers — though only
	// intermittently — so login prefers it and retries through the noise.
	nativeAuthEndpoint = "https://" + PrivateAuthDomain + PrivateAuthAPIPathNativeLogin
	legacyAuthEndpoint = "https://" + PrivateAppStoreAPIDomain + PrivateAppStoreAPIPathAuthenticate
)

var (
	maxLoginAttempts = 12
	loginRetryDelay  = 2 * time.Second
)

type LoginInput struct {
	Email    string
	Password string
	AuthCode string
	Endpoint string
}

type LoginOutput struct {
	Account Account
}

func (t *appstore) Login(input LoginInput) (LoginOutput, error) {
	macAddr, err := t.machine.MacAddress()
	if err != nil {
		return LoginOutput{}, fmt.Errorf("failed to get mac address: %w", err)
	}

	guid := strings.ReplaceAll(strings.ToUpper(macAddr), ":", "")

	acc, err := t.login(input.Email, input.Password, input.AuthCode, guid, input.Endpoint)
	if err != nil {
		return LoginOutput{}, err
	}

	return LoginOutput{
		Account: acc,
	}, nil
}

type loginAddressResult struct {
	FirstName string `plist:"firstName,omitempty"`
	LastName  string `plist:"lastName,omitempty"`
}

type loginAccountResult struct {
	Email   string             `plist:"appleId,omitempty"`
	Address loginAddressResult `plist:"address,omitempty"`
}

type loginResult struct {
	FailureType         string             `plist:"failureType,omitempty"`
	CustomerMessage     string             `plist:"customerMessage,omitempty"`
	Account             loginAccountResult `plist:"accountInfo,omitempty"`
	DirectoryServicesID string             `plist:"dsPersonId,omitempty"`
	PasswordToken       string             `plist:"passwordToken,omitempty"`
}

func (t *appstore) login(email, password, authCode, guid, endpoint string) (Account, error) {
	var lastErr error

	for _, candidate := range authEndpointCandidates(endpoint, guid) {
		acc, err := t.loginAtEndpoint(email, password, authCode, guid, candidate)
		if err == nil {
			return acc, nil
		}

		lastErr = err

		// Anything other than endpoint flakiness (bad credentials, 2FA
		// required, disabled account) is authoritative; another endpoint
		// would return the same answer.
		if !errors.Is(err, errTransientAuthResponse) {
			return Account{}, err
		}
	}

	return Account{}, lastErr
}

// authEndpointCandidates returns the auth endpoints to try, in order. The
// caller-provided endpoint (from the bag) goes first unless it is the legacy
// authenticate URL, which Apple currently hard-rejects; the native endpoint is
// then preferred and the legacy one kept as a last resort.
func authEndpointCandidates(endpoint, guid string) []string {
	ordered := []string{endpoint, nativeAuthEndpoint, legacyAuthEndpoint}

	if strings.Contains(endpoint, PrivateAppStoreAPIPathAuthenticate) {
		ordered = []string{nativeAuthEndpoint, endpoint, legacyAuthEndpoint}
	}

	var candidates []string

	seen := map[string]bool{}

	for _, url := range ordered {
		if url == "" {
			continue
		}

		// Apple's clients pass the machine guid as a query parameter in
		// addition to the plist body.
		if !strings.Contains(url, "?") {
			url += "?guid=" + guid
		}

		if seen[url] {
			continue
		}

		seen[url] = true

		candidates = append(candidates, url)
	}

	return candidates
}

func (t *appstore) loginAtEndpoint(email, password, authCode, guid, endpoint string) (Account, error) {
	var (
		res     http.Result[loginResult]
		lastErr error
	)

	redirect := ""
	attempt := 1

	for try := 1; try <= maxLoginAttempts; try++ {
		request := t.loginRequest(email, password, authCode, guid, endpoint, attempt)
		if redirect != "" {
			request.URL, redirect = redirect, ""
		}

		res, lastErr = t.loginClient.Send(request)
		if lastErr != nil {
			// HTML and empty bodies fail plist parsing; retry through them.
			time.Sleep(loginRetryDelay)
			continue
		}

		if isRedirectStatus(res.StatusCode) {
			location, err := res.GetHeader("location")
			if err != nil {
				// A redirect without a Location header is one of the
				// transient failure modes, not a real redirect.
				lastErr = fmt.Errorf("HTTP %d without location header", res.StatusCode)

				time.Sleep(loginRetryDelay)
				continue
			}

			// The pod redirect is part of the same authentication attempt;
			// Apple expects the original body, including its attempt value.
			redirect = location

			continue
		}

		if isTransientLoginResult(res) {
			lastErr = fmt.Errorf("HTTP %d with empty body", res.StatusCode)

			time.Sleep(loginRetryDelay)
			continue
		}

		if attempt == 1 && res.Data.FailureType == FailureTypeInvalidCredentials {
			attempt = 2

			continue
		}

		return t.processLoginResult(res, password, authCode)
	}

	if lastErr == nil {
		lastErr = errors.New("too many attempts")
	}

	return Account{}, fmt.Errorf("%w: %s (%s)", errTransientAuthResponse, lastErr, endpoint)
}

func isRedirectStatus(statusCode int) bool {
	switch statusCode {
	case gohttp.StatusMovedPermanently,
		gohttp.StatusFound,
		gohttp.StatusSeeOther,
		gohttp.StatusTemporaryRedirect,
		gohttp.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func isTransientLoginResult(res http.Result[loginResult]) bool {
	if res.Data.FailureType != "" || res.Data.CustomerMessage != "" || res.Data.PasswordToken != "" {
		return false
	}

	switch res.StatusCode {
	case gohttp.StatusNoContent,
		gohttp.StatusForbidden,
		gohttp.StatusNotFound,
		gohttp.StatusInternalServerError,
		gohttp.StatusBadGateway,
		gohttp.StatusServiceUnavailable,
		gohttp.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func (t *appstore) processLoginResult(res http.Result[loginResult], password, authCode string) (Account, error) {
	if res.Data.FailureType == "" && authCode == "" && res.Data.CustomerMessage == CustomerMessageBadLogin {
		return Account{}, ErrAuthCodeRequired
	}

	if res.Data.FailureType == "" && res.Data.CustomerMessage == CustomerMessageAccountDisabled {
		return Account{}, NewErrorWithMetadata(errors.New("account is disabled"), res)
	}

	if res.Data.FailureType != "" {
		if res.Data.CustomerMessage != "" {
			return Account{}, NewErrorWithMetadata(errors.New(res.Data.CustomerMessage), res)
		}

		return Account{}, NewErrorWithMetadata(errors.New("something went wrong"), res)
	}

	if res.StatusCode != gohttp.StatusOK || res.Data.PasswordToken == "" || res.Data.DirectoryServicesID == "" {
		return Account{}, NewErrorWithMetadata(errors.New("something went wrong"), res)
	}

	sf, err := res.GetHeader(HTTPHeaderStoreFront)
	if err != nil {
		return Account{}, NewErrorWithMetadata(fmt.Errorf("failed to get storefront header: %w", err), res)
	}

	pod, err := res.GetHeader(HTTPHeaderPod)
	if err != nil && !errors.Is(err, http.ErrHeaderNotFound) {
		return Account{}, NewErrorWithMetadata(fmt.Errorf("failed to get pod header: %w", err), res)
	}

	addr := res.Data.Account.Address
	acc := Account{
		Name:                strings.Join([]string{addr.FirstName, addr.LastName}, " "),
		Email:               res.Data.Account.Email,
		PasswordToken:       res.Data.PasswordToken,
		DirectoryServicesID: res.Data.DirectoryServicesID,
		StoreFront:          sf,
		Password:            password,
		Pod:                 pod,
	}

	data, err := json.Marshal(acc)
	if err != nil {
		return Account{}, fmt.Errorf("failed to marshal json: %w", err)
	}

	err = t.keychain.Set("account", data)
	if err != nil {
		return Account{}, fmt.Errorf("failed to save account in keychain: %w", err)
	}

	return acc, nil
}

func (t *appstore) loginRequest(email, password, authCode, guid, endpoint string, attempt int) http.Request {
	return http.Request{
		Method:         http.MethodPOST,
		URL:            endpoint,
		ResponseFormat: http.ResponseFormatXML,
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
		Payload: &http.XMLPayload{
			Content: map[string]interface{}{
				"appleId":  email,
				"attempt":  strconv.Itoa(attempt),
				"guid":     guid,
				"password": fmt.Sprintf("%s%s", password, strings.ReplaceAll(authCode, " ", "")),
				"rmp":      "0",
				"why":      "signIn",
			},
		},
	}
}
