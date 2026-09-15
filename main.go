// Package main implements the cline CLIProxyAPI dynamic plugin.
//
// cline wraps Cline (https://cline.bot) as a cliproxy provider: it performs
// the WorkOS device-authorization login flow, refreshes access tokens (with
// refresh-token rotation persisted back to the host), syncs the upstream
// model catalog, and forwards OpenAI-compatible chat completion requests to
// https://api.cline.bot/api/v1/chat/completions.
//
// Protocol reverse-engineered from pingmike2/cline2api-workers (MIT).
// Built with -buildmode=c-shared and exports the cliproxy C ABI entry points.
package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

static int cl_call_host(cliproxy_host_api* api, const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	return api->call(api->host_ctx, method, request, request_len, response);
}
static void cl_free_host_buffer(cliproxy_host_api* api, void* ptr, size_t len) {
	api->free_buffer(ptr, len);
}

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	providerName = "cline"

	workosDevice   = "https://api.workos.com/user_management/authorize/device"
	workosAuth     = "https://api.workos.com/user_management/authenticate"
	clineAPIBase   = "https://api.cline.bot/api/v1"
	clineRegister  = clineAPIBase + "/auth/register"
	clineRefresh   = clineAPIBase + "/auth/refresh"
	clineModels    = clineAPIBase + "/models"
	clineChat      = clineAPIBase + "/chat/completions"
	// The authoritative free-model catalog — NOT /v1/models (which lists 400+
	// models across all tiers). The `free` array here is Cline's own
	// definition of what a free account can call.
	clineRecommended = clineAPIBase + "/ai/cline/recommended-models"
	workosClientID = "client_01K3A541FN8TA3EPPHTD2325AR"

	// The free upstream channel (deepseek/*, :free models) breaks under
	// concurrent requests (empty responses) — serialize + 800ms gap, same as
	// the workers version.
	minUpstreamGap = 800 * time.Millisecond

	loginTTL     = 10 * time.Minute
	modelsTTL    = 30 * time.Minute
	cooldownCap  = 6 * time.Hour
	retryMax     = 4
	emptyRetryMax = 3
)

// loginCtx holds one in-flight WorkOS device login flow.
type loginCtx struct {
	deviceCode string
	interval   int
	expires    time.Time
	client     *http.Client // isolated cookie jar for THIS flow — one login's
	// WorkOS/Cline device cookies must never leak into the next login
	// (upstream fingerprinting flags same-device registrations).
}

var (
	hostAPI        *C.cliproxy_host_api
	loginStates    sync.Map // deviceCode(string) -> *loginCtx
	modelsCache    []pluginapi.ModelInfo
	modelsCacheAt  time.Time
	modelsMu       sync.Mutex
	modelsSyncOnce sync.Once
	clientOnce     sync.Once
	sharedClient   *http.Client
	accountClients sync.Map // accountKey -> *http.Client, per-account isolated cookie jar
	gateMu         sync.Mutex
	lastGateAt     time.Time
)

// fallbackModels mirrors the authoritative recommended-models `free` catalog.
func fallbackModels() []pluginapi.ModelInfo {
	free := []recommendedModel{
		{ID: "cline-free/deepseek-v4.1-flash", Name: "Deepseek-v4.1-Flash"},
		{ID: "cline-free/muse-spark-1.3-contributor", Name: "Muse Spark 1.3 Contributor"},
		{ID: "z-ai/glm-5.3-flash", Name: "glm-5.3-flash"},
		{ID: "cline-free/solar-pro4", Name: "Solar Pro 4"},
		{ID: "poolside/laguna-s-2.1:free", Name: "laguna-s-2.1:free"},
	}
	out := make([]pluginapi.ModelInfo, 0, len(free))
	for _, m := range free {
		out = append(out, pluginapi.ModelInfo{
			ID:          m.ID,
			Object:      "model",
			OwnedBy:     "cline",
			Name:        m.ID,
			DisplayName: m.Name,
			Type:        "chat",
		})
	}
	return out
}

func cachedModels() []pluginapi.ModelInfo {
	modelsMu.Lock()
	defer modelsMu.Unlock()
	if len(modelsCache) > 0 {
		return modelsCache
	}
	return nil
}

// modelsSyncLoop refreshes the upstream model catalog in the background.
// The registration path always returns cached/fallback models immediately
// so plugin registration never blocks on a slow upstream fetch.
func modelsSyncLoop() {
	modelsSyncOnce.Do(func() {
		go func() {
			refreshModels()
			ticker := time.NewTicker(modelsTTL)
			defer ticker.Stop()
			for range ticker.C {
				refreshModels()
			}
		}()
	})
}

type recommendedModelsResponse struct {
	Recommended []recommendedModel `json:"recommended"`
	Free        []recommendedModel `json:"free"`
	ClinePass   []recommendedModel `json:"clinePass"`
	ClineCloud  []recommendedModel `json:"clineCloud"`
}

type recommendedModel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func refreshModels() {
	req, err := http.NewRequest(http.MethodGet, clineRecommended, nil)
	if err != nil {
		fmt.Printf("[cline] models fetch setup error: %v\n", err)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (cline2api)")
	client := sharedHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[cline] models fetch error: %v\n", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[cline] models fetch HTTP %d\n", resp.StatusCode)
		return
	}
	raw, _ := io.ReadAll(resp.Body)
	var mr recommendedModelsResponse
	if json.Unmarshal(raw, &mr) != nil || len(mr.Free) == 0 {
		fmt.Printf("[cline] models fetch parse error (bytes=%d)\n", len(raw))
		return
	}
	list := make([]pluginapi.ModelInfo, 0, len(mr.Free))
	for _, m := range mr.Free {
		id := strings.TrimSpace(m.ID)
		if id == "" {
			continue
		}
		list = append(list, pluginapi.ModelInfo{
			ID:          id,
			Object:      "model",
			OwnedBy:     "cline",
			Name:        id,
			DisplayName: firstNonEmpty(m.Name, id),
			Type:        "chat",
		})
	}
	modelsMu.Lock()
	modelsCache = list
	modelsCacheAt = time.Now()
	modelsMu.Unlock()
}

func currentModels() []pluginapi.ModelInfo {
	if m := cachedModels(); len(m) > 0 {
		return m
	}
	// Registration raced the background sync (CPA asks for models before the
	// init goroutine finishes the first upstream fetch). Do one synchronous
	// refresh with a bounded wait so the real free catalog is registered;
	// fall back to the built-in list only if the upstream is unreachable.
	done := make(chan struct{})
	go func() {
		refreshModels()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
	}
	if m := cachedModels(); len(m) > 0 {
		return m
	}
	return fallbackModels()
}

// ---------------------------------------------------------------------------
// C ABI exports
// ---------------------------------------------------------------------------

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	hostAPI = host
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	modelsSyncLoop()
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope("plugin_error", errHandle.Error()))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, len C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

// hostCall invokes a host RPC method (async stream emit/close).
func hostCall(method string, request []byte) ([]byte, error) {
	if hostAPI == nil || hostAPI.call == nil {
		return nil, fmt.Errorf("host API unavailable")
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var cReq unsafe.Pointer
	var reqLen C.size_t
	if len(request) > 0 {
		cReq = C.CBytes(request)
		defer C.free(cReq)
		reqLen = C.size_t(len(request))
	}
	var resp C.cliproxy_buffer
	rc := C.cl_call_host(hostAPI, cMethod, (*C.uint8_t)(cReq), reqLen, &resp)
	var out []byte
	if resp.ptr != nil && resp.len > 0 {
		out = C.GoBytes(resp.ptr, C.int(resp.len))
	}
	if resp.ptr != nil && hostAPI.free_buffer != nil {
		C.cl_free_host_buffer(hostAPI, resp.ptr, resp.len)
	}
	if rc != 0 {
		return out, fmt.Errorf("host call %s returned %d", method, int(rc))
	}
	return out, nil
}

func streamEmit(streamID string, payload []byte) error {
	if streamID == "" {
		return fmt.Errorf("no stream id")
	}
	body, _ := json.Marshal(map[string]any{"stream_id": streamID, "payload": payload})
	_, err := hostCall(pluginabi.MethodHostStreamEmit, body)
	return err
}

func streamEmitError(streamID, message string) {
	if streamID == "" {
		return
	}
	errJSON, _ := json.Marshal(map[string]any{"error": map[string]any{"message": message}})
	_ = streamEmit(streamID, errJSON)
}

func streamClose(streamID string) {
	if streamID == "" {
		return
	}
	body, _ := json.Marshal(map[string]any{"stream_id": streamID})
	_, _ = hostCall(pluginabi.MethodHostStreamClose, body)
}

// ---------------------------------------------------------------------------
// RPC dispatch
// ---------------------------------------------------------------------------

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type identifierResponse struct {
	Identifier string `json:"identifier"`
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

type registrationCapability struct {
	ModelProvider         bool                         `json:"model_provider"`
	AuthProvider          bool                         `json:"auth_provider"`
	Executor              bool                         `json:"executor"`
	ExecutorModelScope    pluginapi.ExecutorModelScope `json:"executor_model_scope"`
	ExecutorInputFormats  []string                     `json:"executor_input_formats,omitempty"`
	ExecutorOutputFormats []string                     `json:"executor_output_formats,omitempty"`
}

type streamResponse struct {
	Headers http.Header                     `json:"headers,omitempty"`
	Chunks  []pluginapi.ExecutorStreamChunk `json:"chunks,omitempty"`
}

func clineRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             providerName,
			Version:          "1.0.0",
			Author:           "BevalZ (protocol from pingmike2/cline2api-workers)",
			GitHubRepository: "https://github.com/BevalZ/cline-cliproxy",
			Logo:             "data:image/png;base64," + clineLogoData,
		},
		Capabilities: registrationCapability{
			ModelProvider:         true,
			AuthProvider:          true,
			Executor:              true,
			ExecutorModelScope:    pluginapi.ExecutorModelScopeBoth,
			ExecutorInputFormats:  []string{"chat-completions"},
			ExecutorOutputFormats: []string{"chat-completions"},
		},
	}
}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return okEnvelope(clineRegistration())
	case pluginabi.MethodModelStatic, pluginabi.MethodModelForAuth:
		return okEnvelope(pluginapi.ModelResponse{Provider: providerName, Models: currentModels()})
	case pluginabi.MethodAuthIdentifier:
		return okEnvelope(identifierResponse{Identifier: providerName})
	case pluginabi.MethodAuthParse:
		return handleParseAuth(request)
	case pluginabi.MethodAuthLoginStart:
		return handleStartLogin(request)
	case pluginabi.MethodAuthLoginPoll:
		return handlePollLogin(request)
	case pluginabi.MethodAuthRefresh:
		return handleRefreshAuth(request)
	case pluginabi.MethodExecutorIdentifier:
		return okEnvelope(identifierResponse{Identifier: providerName})
	case pluginabi.MethodExecutorExecute:
		return handleExecExecute(request)
	case pluginabi.MethodExecutorExecuteStream:
		return handleExecStream(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

// ---------------------------------------------------------------------------
// Stored auth
// ---------------------------------------------------------------------------

type storedAuth struct {
	Auth    storedTokens  `json:"auth"`
	Account storedAccount `json:"account"`
}

type storedTokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    int64  `json:"expiresAt"` // unix millis
}

type storedAccount struct {
	Email    string `json:"email"`
	Nickname string `json:"nickname"`
}

func parseStored(raw []byte) (*storedAuth, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty auth storage")
	}
	var sa storedAuth
	if err := json.Unmarshal(raw, &sa); err != nil {
		return nil, fmt.Errorf("storage_parse_error: %w", err)
	}
	if sa.Auth.RefreshToken == "" {
		return nil, fmt.Errorf("parse_error: missing refreshToken")
	}
	return &sa, nil
}

// securityHash returns a deterministic short hex digest used to key an account.
func securityHash(value string) string {
	if value == "" {
		return "unknown"
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func accountUID(sa *storedAuth) string {
	if sa != nil && strings.TrimSpace(sa.Account.Email) != "" {
		return strings.TrimSpace(sa.Account.Email)
	}
	if sa != nil && sa.Auth.RefreshToken != "" {
		return securityHash(sa.Auth.RefreshToken)
	}
	return "unknown"
}

func toAuthData(sa *storedAuth) pluginapi.AuthData {
	storage, _ := json.Marshal(sa)
	// Each account gets its own stable ID and auth file derived from the
	// account email; without it every login would overwrite the same file.
	// Emails contain chars unsafe for filenames, so hash the UID.
	uid := accountUID(sa)
	id := providerName + "-" + securityHash(uid)
	label := "Cline " + uid
	if len(label) > 48 {
		label = label[:48]
	}
	return pluginapi.AuthData{
		Provider:    providerName,
		ID:          id,
		FileName:    id + ".json",
		Label:       label,
		StorageJSON: storage,
		Metadata:    map[string]any{"type": providerName},
	}
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

func sharedHTTPClient() *http.Client {
	clientOnce.Do(func() {
		jar, _ := cookiejar.New(nil)
		transport := &http.Transport{
			MaxIdleConns:        20,
			IdleConnTimeout:     90 * time.Second,
			MaxIdleConnsPerHost: 5,
		}
		// api.workos.com and api.cline.bot are foreign and unreliable from CN —
		// route everything through the local Clash proxy (same as workbuddy-int).
		proxyURL, err := url.Parse("http://127.0.0.1:7890")
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
		sharedClient = &http.Client{
			Timeout:   180 * time.Second,
			Transport: transport,
			Jar:       jar,
		}
	})
	return sharedClient
}

// newLoginClient builds an isolated client with its own cookie jar so one
// login flow's WorkOS/Cline device cookies never leak into another.
func newLoginClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout:   sharedHTTPClient().Timeout,
		Transport: sharedHTTPClient().Transport,
		Jar:       jar,
	}
}

// accountKey returns a stable per-account isolation key.
func accountKey(sa *storedAuth) string {
	return securityHash(accountUID(sa))
}

// accountHTTPClient returns a client whose cookie jar is isolated per
// account. The transport (connection pool) is shared with the global
// client, so per-account isolation costs nothing in connection reuse.
func accountHTTPClient(sa *storedAuth) *http.Client {
	key := accountKey(sa)
	if existing, ok := accountClients.Load(key); ok {
		return existing.(*http.Client)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout:   sharedHTTPClient().Timeout,
		Transport: sharedHTTPClient().Transport,
		Jar:       jar,
	}
	actual, _ := accountClients.LoadOrStore(key, client)
	return actual.(*http.Client)
}

// gateUpstream serializes upstream chat calls with a minimum gap: the free
// upstream channel returns empty responses under concurrency.
func gateUpstream() {
	gateMu.Lock()
	defer gateMu.Unlock()
	now := time.Now()
	if wait := minUpstreamGap - now.Sub(lastGateAt); wait > 0 {
		time.Sleep(wait)
	}
	lastGateAt = time.Now()
}

func clineFingerprintHeaders(accessToken, taskID string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer workos:"+accessToken)
	h.Set("Content-Type", "application/json")
	h.Set("User-Agent", "Cline/3.0.47")
	h.Set("HTTP-Referer", "https://cline.bot")
	h.Set("X-Title", "Cline")
	h.Set("X-IS-MULTIROOT", "false")
	h.Set("X-CLIENT-TYPE", "cline-sdk")
	h.Set("X-CLIENT-VERSION", "3.0.47")
	h.Set("X-PLATFORM", "terminal")
	h.Set("X-PLATFORM-VERSION", "3.0.47")
	h.Set("X-CORE-VERSION", "0.0.66")
	h.Set("X-Task-ID", taskID)
	return h
}

func postForm(client *http.Client, fullURL string, form url.Values) (json.RawMessage, error) {
	req, err := http.NewRequest(http.MethodPost, fullURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	return raw, nil
}

func postJSON(client *http.Client, fullURL string, body any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, fullURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	return raw, nil
}

// ---------------------------------------------------------------------------
// Auth handlers
// ---------------------------------------------------------------------------

func handleParseAuth(raw []byte) ([]byte, error) {
	var req pluginapi.AuthParseRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	sa, err := parseStored(req.RawJSON)
	if err != nil {
		return okEnvelope(pluginapi.AuthParseResponse{Handled: false})
	}
	return okEnvelope(pluginapi.AuthParseResponse{
		Handled: true,
		Auth:    toAuthData(sa),
	})
}

// handleStartLogin starts a WorkOS device authorization flow.
func handleStartLogin(raw []byte) ([]byte, error) {
	client := newLoginClient()
	resp, err := postForm(client, workosDevice, url.Values{"client_id": {workosClientID}})
	if err != nil {
		return nil, fmt.Errorf("workos device: %w", err)
	}
	var dev struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		Interval                int    `json:"interval"`
		ExpiresIn               int    `json:"expires_in"`
	}
	if err := json.Unmarshal(resp, &dev); err != nil {
		return nil, fmt.Errorf("workos device parse: %w", err)
	}
	if dev.DeviceCode == "" {
		return nil, fmt.Errorf("workos device: missing device_code")
	}
	authURL := dev.VerificationURIComplete
	if authURL == "" {
		authURL = dev.VerificationURI
	}
	if dev.Interval < 5 {
		dev.Interval = 5
	}
	ttl := time.Duration(dev.ExpiresIn) * time.Second
	if ttl <= 0 || ttl > loginTTL {
		ttl = loginTTL
	}
	loginStates.Store(dev.DeviceCode, &loginCtx{
		deviceCode: dev.DeviceCode,
		interval:   dev.Interval,
		expires:    time.Now().Add(ttl),
		client:     client,
	})
	return okEnvelope(pluginapi.AuthLoginStartResponse{
		Provider:  providerName,
		URL:       authURL,
		State:     dev.DeviceCode,
		ExpiresAt: time.Now().Add(ttl).UTC(),
	})
}

type clineRegisterResponse struct {
	Data struct {
		RefreshToken string `json:"refreshToken"`
		UserInfo     struct {
			Email    string `json:"email"`
			Nickname string `json:"nickname"`
		} `json:"userInfo"`
	} `json:"data"`
}

// handlePollLogin polls WorkOS until the user authorizes, then exchanges the
// WorkOS tokens for a Cline refreshToken via /auth/register.
func handlePollLogin(raw []byte) ([]byte, error) {
	var req pluginapi.AuthLoginPollRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	state := strings.TrimSpace(req.State)
	if state == "" {
		return nil, fmt.Errorf("poll: empty state")
	}
	v, ok := loginStates.Load(state)
	if !ok {
		return nil, fmt.Errorf("poll: unknown state (restart login)")
	}
	lc := v.(*loginCtx)
	if time.Now().After(lc.expires) {
		loginStates.Delete(state)
		return nil, fmt.Errorf("poll: login expired")
	}
	client := lc.client
	if client == nil {
		client = sharedHTTPClient()
	}
	authResp, err := postForm(client, workosAuth, url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {lc.deviceCode},
		"client_id":   {workosClientID},
	})
	if err != nil {
		// Transient network error — keep the flow pending, not failed.
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusPending,
			Message: "workos poll transient error",
		})
	}
	var wa struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Error        string `json:"error"`
	}
	if err := json.Unmarshal(authResp, &wa); err != nil {
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusPending,
			Message: "workos poll parse error",
		})
	}
	switch wa.Error {
	case "":
		// authorized, proceed
	case "authorization_pending", "slow_down":
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusPending,
			Message: "waiting for user authorization",
		})
	default:
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "workos: " + wa.Error,
		})
	}
	if wa.AccessToken == "" {
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusPending,
			Message: "not yet authorized",
		})
	}
	loginStates.Delete(state)

	regRaw, err := postJSON(client, clineRegister, map[string]any{
		"accessToken":  wa.AccessToken,
		"refreshToken": wa.RefreshToken,
	})
	if err != nil {
		return nil, fmt.Errorf("cline register: %w", err)
	}
	var reg clineRegisterResponse
	if err := json.Unmarshal(regRaw, &reg); err != nil {
		return nil, fmt.Errorf("cline register parse: %w", err)
	}
	rt := reg.Data.RefreshToken
	if rt == "" {
		return nil, fmt.Errorf("cline register: no refreshToken")
	}
	sa := &storedAuth{
		Auth: storedTokens{RefreshToken: rt},
		Account: storedAccount{
			Email:    reg.Data.UserInfo.Email,
			Nickname: reg.Data.UserInfo.Nickname,
		},
	}
	return okEnvelope(pluginapi.AuthLoginPollResponse{
		Status: pluginapi.AuthLoginStatusSuccess,
		Auth:   toAuthData(sa),
	})
}

type clineRefreshResponse struct {
	Data struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresAt    any    `json:"expiresAt"`
	} `json:"data"`
}

// handleRefreshAuth refreshes the access token. Cline rotates the refresh
// token on every refresh — persist the rotated value via AuthRefreshResponse.
func handleRefreshAuth(raw []byte) ([]byte, error) {
	var req pluginapi.AuthRefreshRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	sa, err := parseStored(req.StorageJSON)
	if err != nil {
		return nil, fmt.Errorf("refresh: %w", err)
	}
	rawResp, err := postJSON(accountHTTPClient(sa), clineRefresh, map[string]any{
		"refreshToken": sa.Auth.RefreshToken,
		"grantType":    "refresh_token",
	})
	if err != nil {
		return nil, fmt.Errorf("refresh: %w", err)
	}
	var cr clineRefreshResponse
	if err := json.Unmarshal(rawResp, &cr); err != nil {
		return nil, fmt.Errorf("refresh parse: %w", err)
	}
	if cr.Data.AccessToken == "" {
		return nil, fmt.Errorf("refresh_failed: no accessToken")
	}
	sa.Auth.AccessToken = cr.Data.AccessToken
	if strings.TrimSpace(cr.Data.RefreshToken) != "" {
		sa.Auth.RefreshToken = strings.TrimSpace(cr.Data.RefreshToken)
	}
	sa.Auth.ExpiresAt = resolveExpiry(cr.Data.ExpiresAt)
	return okEnvelope(pluginapi.AuthRefreshResponse{Auth: toAuthData(sa)})
}

func resolveExpiry(v any) int64 {
	now := time.Now().UnixMilli()
	switch x := v.(type) {
	case float64:
		// ms epoch
		if x > 1e12 {
			return int64(x) - 60000
		}
		// seconds epoch
		return int64(x)*1000 - 60000
	case string:
		if t, err := time.Parse(time.RFC3339, x); err == nil {
			return t.UnixMilli() - 60000
		}
	}
	return now + 10*time.Minute.Milliseconds()
}

// ---------------------------------------------------------------------------
// Executor: upstream request + account pool
// ---------------------------------------------------------------------------

// poolAcct is a pooled account used for rotation on 429/empty responses.
type poolAcct struct {
	sa           *storedAuth
	cooldownUntil time.Time
}

var acctPool sync.Map // securityHash(email|refresh) -> *poolAcct

func poolKey(sa *storedAuth) string {
	return securityHash(accountUID(sa))
}

func rememberAccount(sa *storedAuth) {
	if sa == nil || sa.Auth.RefreshToken == "" {
		return
	}
	key := poolKey(sa)
	if _, ok := acctPool.Load(key); ok {
		return
	}
	acctPool.Store(key, &poolAcct{sa: sa})
}

func poolAccounts() []*poolAcct {
	var out []*poolAcct
	acctPool.Range(func(_, v any) bool {
		out = append(out, v.(*poolAcct))
		return true
	})
	return out
}

func coolAccount(sa *storedAuth, d time.Duration) {
	if sa == nil {
		return
	}
	if v, ok := acctPool.Load(poolKey(sa)); ok {
		v.(*poolAcct).cooldownUntil = time.Now().Add(d)
	}
}

func accountCooled(sa *storedAuth) bool {
	if sa == nil {
		return false
	}
	if v, ok := acctPool.Load(poolKey(sa)); ok {
		return time.Now().Before(v.(*poolAcct).cooldownUntil)
	}
	return false
}

// parseCooldown extracts the upstream cooldown hint ("Try again in 2h 51m"),
// capped at cooldownCap. Defaults: 429 → 5min, other → 60s.
func parseCooldown(body string, status int) time.Duration {
	re := `try again in (?:(\d+)\s*h)?\s*(?:(\d+)\s*m)?\s*(?:(\d+)\s*s)?`
	m := regexpMatch(re, body)
	if len(m) == 4 {
		h := atoiSafe(m[1])
		min := atoiSafe(m[2])
		s := atoiSafe(m[3])
		ms := time.Duration(h*3600+min*60+s) * time.Second
		if ms > 0 {
			if ms > cooldownCap {
				ms = cooldownCap
			}
			return ms
		}
	}
	if status == http.StatusTooManyRequests {
		return 5 * time.Minute
	}
	return 60 * time.Second
}

func regexpMatch(pattern, s string) []string {
	re := regexp.MustCompile(pattern)
	return re.FindStringSubmatch(s)
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// isLimitHit reports whether the upstream response signals quota/rate-limit
// (needs account switch): 429, 5xx with "empty response content", or a 200
// non-stream body containing "empty response content".
func isLimitHit(resp *http.Response, bodyText string, isStream bool) bool {
	if resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if resp.StatusCode >= 500 && strings.Contains(bodyText, "empty response content") {
		return true
	}
	if resp.StatusCode == http.StatusOK && !isStream && strings.Contains(bodyText, "empty response content") {
		return true
	}
	return false
}

// upstreamChat performs one gated chat request with the given account.
func upstreamChat(sa *storedAuth, body []byte, taskID string) (*http.Response, error) {
	gateUpstream()
	// Refresh access token if we don't have one or it's expired.
	if sa.Auth.AccessToken == "" || time.Now().UnixMilli() >= sa.Auth.ExpiresAt {
		rawResp, err := postJSON(accountHTTPClient(sa), clineRefresh, map[string]any{
			"refreshToken": sa.Auth.RefreshToken,
			"grantType":    "refresh_token",
		})
		if err != nil {
			return nil, fmt.Errorf("token refresh: %w", err)
		}
		var cr clineRefreshResponse
		if err := json.Unmarshal(rawResp, &cr); err != nil {
			return nil, fmt.Errorf("token refresh parse: %w", err)
		}
		if cr.Data.AccessToken == "" {
			return nil, fmt.Errorf("token refresh: no accessToken")
		}
		sa.Auth.AccessToken = cr.Data.AccessToken
		if strings.TrimSpace(cr.Data.RefreshToken) != "" {
			sa.Auth.RefreshToken = strings.TrimSpace(cr.Data.RefreshToken)
		}
		sa.Auth.ExpiresAt = resolveExpiry(cr.Data.ExpiresAt)
	}
	req, err := http.NewRequest(http.MethodPost, clineChat, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, vs := range clineFingerprintHeaders(sa.Auth.AccessToken, taskID) {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := accountHTTPClient(sa).Do(req)
	if err != nil {
		return nil, fmt.Errorf("http_error: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// token invalid — force refresh on next attempt
		sa.Auth.AccessToken = ""
		sa.Auth.ExpiresAt = 0
	}
	return resp, nil
}

// buildUpstreamBody enriches the client payload for the Cline upstream:
// stream forced on (free deepseek channel rejects non-stream), session_id,
// reasoning_effort default, max_tokens default.
func buildUpstreamBody(payload, original []byte) []byte {
	src := payload
	if len(src) == 0 {
		src = original
	}
	var obj map[string]any
	if json.Unmarshal(src, &obj) != nil {
		out, _ := json.Marshal(map[string]any{"messages": []any{}, "stream": true})
		return out
	}
	obj["stream"] = true
	if _, ok := obj["max_tokens"]; !ok {
		if _, ok2 := obj["max_completion_tokens"]; !ok2 {
			obj["max_tokens"] = 128000
		}
	}
	if _, ok := obj["reasoning_effort"]; !ok {
		obj["reasoning_effort"] = "high"
	}
	if _, ok := obj["session_id"]; !ok {
		obj["session_id"] = "sess_" + fmt.Sprintf("%d", time.Now().UnixMilli())
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return src
	}
	return out
}

// unwrapData strips the upstream {data:{...}} wrapper.
func unwrapData(obj map[string]any) map[string]any {
	if d, ok := obj["data"].(map[string]any); ok {
		if _, hasChoices := d["choices"]; hasChoices {
			return d
		}
		if _, hasID := d["id"]; hasID {
			return d
		}
		if _, hasUsage := d["usage"]; hasUsage {
			return d
		}
	}
	return obj
}

// emptyContent reports whether an aggregated completion has no visible content
// (reasoning-only streams happen on the free channel).
func emptyContent(completion map[string]any) bool {
	choices, _ := completion["choices"].([]any)
	for _, c := range choices {
		choice, _ := c.(map[string]any)
		msg, _ := choice["message"].(map[string]any)
		if msg == nil {
			continue
		}
		if content, _ := msg["content"].(string); strings.TrimSpace(content) != "" {
			return false
		}
		if tcs, ok := msg["tool_calls"].([]any); ok && len(tcs) > 0 {
			return false
		}
	}
	return true
}

func handleExecExecute(raw []byte) ([]byte, error) {
	var req pluginapi.ExecutorRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	sa, err := parseStored(req.StorageJSON)
	if err != nil {
		return nil, err
	}
	rememberAccount(sa)
	body := buildUpstreamBody(req.Payload, req.OriginalRequest)
	taskID := "sess_" + fmt.Sprintf("%d", time.Now().UnixMilli())

	// Attempt with the request's own account, then rotate through the pool
	// on quota/empty signals (mirrors cline2api-workers).
	var lastErr error
	var lastResp *http.Response
	for attempt := 0; attempt <= retryMax; attempt++ {
		sa := sa
		if attempt > 0 {
			sa = nextAvailableAccount(sa)
		}
		if sa == nil {
			break
		}
		if accountCooled(sa) {
			continue
		}
		resp, err := upstreamChat(sa, body, taskID)
		if err != nil {
			lastErr = err
			coolAccount(sa, 60*time.Second)
			continue
		}
		lastResp = resp
		if resp.StatusCode >= 400 {
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			text := string(respBody)
			if isLimitHit(resp, text, false) {
				coolAccount(sa, parseCooldown(text, resp.StatusCode))
				continue
			}
			return nil, fmt.Errorf("upstream %d: %s", resp.StatusCode, truncate(text, 200))
		}
		completion, aggErr := aggregateCompletion(resp.Body, req.Model)
		resp.Body.Close()
		if aggErr != nil {
			return nil, aggErr
		}
		if !emptyContent(completion) {
			payload, _ := json.Marshal(completion)
			return okEnvelope(pluginapi.ExecutorResponse{Payload: payload})
		}
		// Empty content (reasoning-only stream) — cooldown and rotate.
		coolAccount(sa, 30*time.Second)
		lastErr = fmt.Errorf("empty content from account")
	}
	if lastErr != nil {
		return nil, lastErr
	}
	if lastResp != nil {
		return nil, fmt.Errorf("upstream %d", lastResp.StatusCode)
	}
	return nil, fmt.Errorf("no available accounts")
}

// nextAvailableAccount returns a pooled account other than the current one
// that is not in cooldown; falls back to the current account.
func nextAvailableAccount(current *storedAuth) *storedAuth {
	curKey := poolKey(current)
	now := time.Now()
	for _, acct := range poolAccounts() {
		if poolKey(acct.sa) == curKey {
			continue
		}
		if now.Before(acct.cooldownUntil) {
			continue
		}
		return acct.sa
	}
	return current
}

// executorStreamRequest wraps the host's execute_stream RPC.
type executorStreamRequest struct {
	pluginapi.ExecutorRequest
	StreamID       string `json:"stream_id,omitempty"`
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

func handleExecStream(raw []byte) ([]byte, error) {
	var req executorStreamRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	sa, err := parseStored(req.StorageJSON)
	if err != nil {
		return nil, err
	}
	rememberAccount(sa)
	body := buildUpstreamBody(req.Payload, req.OriginalRequest)
	taskID := "sess_" + fmt.Sprintf("%d", time.Now().UnixMilli())
	headers := streamHeaders()
	sseFramed := clientNeedsSSEFrame(req.Metadata)

	// Connect phase with account rotation on quota/empty signals; once an
	// upstream 200 arrives, hand the body to the pump goroutine.
	var lastResp *http.Response
	var lastErr error
	for attempt := 0; attempt <= retryMax; attempt++ {
		acct := sa
		if attempt > 0 {
			acct = nextAvailableAccount(sa)
		}
		if acct == nil || accountCooled(acct) {
			continue
		}
		resp, err := upstreamChat(acct, body, taskID)
		if err != nil {
			lastErr = err
			coolAccount(acct, 60*time.Second)
			continue
		}
		if resp.StatusCode >= 400 {
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			text := string(respBody)
			if isLimitHit(resp, text, true) {
				coolAccount(acct, parseCooldown(text, resp.StatusCode))
				continue
			}
			lastErr = fmt.Errorf("upstream %d: %s", resp.StatusCode, truncate(text, 200))
			break
		}
		lastResp = resp
		break
	}
	if lastResp == nil {
		if lastErr != nil {
			if req.StreamID != "" {
				streamEmitError(req.StreamID, lastErr.Error())
				streamClose(req.StreamID)
				return okEnvelope(streamResponse{Headers: headers})
			}
			return nil, lastErr
		}
		return nil, fmt.Errorf("no available accounts")
	}

	if req.StreamID == "" {
		chunks, errChunks := collectSSE(lastResp.Body, sseFramed, req.Model)
		lastResp.Body.Close()
		if errChunks != nil {
			return nil, errChunks
		}
		return okEnvelope(streamResponse{Headers: headers, Chunks: chunks})
	}

	// Async: pump in the background via host.stream.emit.
	httpResp := lastResp
	go func() {
		defer httpResp.Body.Close()
		pumpSSE(httpResp.Body, req.StreamID, sseFramed, req.Model)
	}()
	return okEnvelope(streamResponse{Headers: headers})
}

func streamHeaders() http.Header {
	h := http.Header{}
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	return h
}

func clientNeedsSSEFrame(metadata map[string]any) bool {
	path, _ := metadata["request_path"].(string)
	switch strings.ToLower(strings.TrimSpace(path)) {
	case "/v1/chat/completions", "/v1/completions":
		return false
	default:
		return true
	}
}

// pumpSSE reads the upstream SSE stream and emits cleaned chunks to the host
// stream (unwrap data wrapper, external model id, tool_calls preserved).
func pumpSSE(r io.Reader, streamID string, sseFramed bool, externalModel string) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		content := stripDataPrefix(scanner.Text())
		if content == "" || content == "[DONE]" {
			continue
		}
		obj := map[string]any{}
		if json.Unmarshal([]byte(content), &obj) != nil {
			continue
		}
		obj = unwrapData(obj)
		if externalModel != "" {
			obj["model"] = externalModel
		}
		cleaned := cleanChunkJSON(obj)
		if cleaned == "" {
			continue
		}
		if sseFramed {
			cleaned = "data: " + cleaned
		}
		if err := streamEmit(streamID, []byte(cleaned)); err != nil {
			break
		}
	}
	streamClose(streamID)
}

func collectSSE(r io.Reader, sseFramed bool, externalModel string) ([]pluginapi.ExecutorStreamChunk, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var chunks []pluginapi.ExecutorStreamChunk
	for scanner.Scan() {
		content := stripDataPrefix(scanner.Text())
		if content == "" || content == "[DONE]" {
			continue
		}
		obj := map[string]any{}
		if json.Unmarshal([]byte(content), &obj) != nil {
			continue
		}
		obj = unwrapData(obj)
		if externalModel != "" {
			obj["model"] = externalModel
		}
		cleaned := cleanChunkJSON(obj)
		if cleaned == "" {
			continue
		}
		if sseFramed {
			cleaned = "data: " + cleaned
		}
		chunks = append(chunks, pluginapi.ExecutorStreamChunk{Payload: []byte(cleaned)})
	}
	if err := scanner.Err(); err != nil {
		return chunks, err
	}
	return chunks, nil
}

// cleanChunkJSON strips empty-valued top-level delta fields but NEVER inside
// tool_calls (upstream streams tool calls as fragments — deleting empty fields
// corrupts the stream and breaks tool calling).
func cleanChunkJSON(obj map[string]any) string {
	if choices, ok := obj["choices"].([]any); ok {
		for _, c := range choices {
			choice, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if delta, ok := choice["delta"].(map[string]any); ok {
				if _, hasTools := delta["tool_calls"]; !hasTools {
					for k, v := range delta {
						if isEmptyValue(v) {
							delete(delta, k)
						}
					}
				}
			}
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return ""
	}
	return string(out)
}

func isEmptyValue(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

// aggregateCompletion folds an upstream SSE stream into one chat.completion
// object, merging tool_call fragments by index (international plugin lesson).
func aggregateCompletion(r io.Reader, model string) (map[string]any, error) {
	var content, reasoning, role, respModel, respID, finish string
	var created int64
	var usage map[string]any
	var toolCalls []map[string]any
	var toolCallIndex = map[int]map[string]any{}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		data := stripDataPrefix(scanner.Text())
		if data == "" || data == "[DONE]" {
			continue
		}
		chunk := map[string]any{}
		if json.Unmarshal([]byte(data), &chunk) != nil {
			continue
		}
		chunk = unwrapData(chunk)
		if v, ok := chunk["id"].(string); ok && v != "" {
			respID = v
		}
		if v, ok := chunk["model"].(string); ok && v != "" {
			respModel = v
		}
		if v, ok := chunk["created"].(float64); ok {
			created = int64(v)
		}
		if v, ok := chunk["usage"].(map[string]any); ok {
			usage = v
		}
		choices, _ := chunk["choices"].([]any)
		for _, c := range choices {
			choice, _ := c.(map[string]any)
			if delta, ok := choice["delta"].(map[string]any); ok {
				if v, ok := delta["role"].(string); ok && v != "" {
					role = v
				}
				if v, ok := delta["content"].(string); ok {
					content += v
				}
				if v, ok := delta["reasoning_content"].(string); ok {
					reasoning += v
				}
				if v, ok := delta["reasoning"].(string); ok {
					reasoning += v
				}
				if tcs, ok := delta["tool_calls"].([]any); ok {
					for _, tc := range tcs {
						call, ok := tc.(map[string]any)
						if !ok {
							continue
						}
						idx := 0
						if f, ok := call["index"].(float64); ok {
							idx = int(f)
						}
						merged, exists := toolCallIndex[idx]
						if !exists {
							merged = map[string]any{"index": idx}
							toolCallIndex[idx] = merged
							toolCalls = append(toolCalls, merged)
						}
						for k, v := range call {
							if k == "index" {
								continue
							}
							if k == "function" {
								nf, _ := v.(map[string]any)
								mf, _ := merged["function"].(map[string]any)
								if mf == nil {
									mf = map[string]any{}
									merged["function"] = mf
								}
								for fk, fv := range nf {
									if fk == "arguments" {
										if a, ok := fv.(string); ok {
											prev, _ := mf["arguments"].(string)
											mf["arguments"] = prev + a
											continue
										}
									}
									if s, ok := fv.(string); ok && s != "" {
										mf[fk] = fv
									}
								}
								continue
							}
							if s, ok := v.(string); ok && s != "" {
								merged[k] = v
							}
						}
					}
				}
			}
			if v, ok := choice["finish_reason"].(string); ok && v != "" {
				finish = v
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if created == 0 {
		created = time.Now().Unix()
	}
	message := map[string]any{"role": firstNonEmpty(role, "assistant"), "content": content}
	if reasoning != "" {
		message["reasoning_content"] = reasoning
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}
	respModel = firstNonEmpty(respModel, model)
	completion := map[string]any{
		"id":      firstNonEmpty(respID, "gen_"+fmt.Sprintf("%d", time.Now().UnixMilli())),
		"object":  "chat.completion",
		"created": created,
		"model":   respModel,
		"choices": []any{map[string]any{
			"index":         0,
			"message":       message,
			"finish_reason": firstNonEmpty(finish, "stop"),
			"logprobs":      nil,
		}},
	}
	if usage != nil {
		completion["usage"] = usage
	} else {
		completion["usage"] = map[string]any{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
	}
	return completion, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func stripDataPrefix(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "data:") {
		return strings.TrimSpace(s[5:])
	}
	return s
}

func okEnvelope(v any) ([]byte, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: payload})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.malloc(C.size_t(len(raw)))
	if ptr == nil {
		return
	}
	C.memcpy(ptr, unsafe.Pointer(&raw[0]), C.size_t(len(raw)))
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
