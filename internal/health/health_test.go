package health

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadyRequiresListenerAndTailnet(t *testing.T) {
	state := &State{Tailnet: func(context.Context) (bool, string) { return true, "tsdnsproxy" }}
	if state.Live() == false || state.Ready(context.Background()) {
		t.Fatalf("startup live=%v ready=%v", state.Live(), state.Ready(context.Background()))
	}
	state.AddListener()
	if !state.Ready(context.Background()) {
		t.Fatal("expected ready")
	}
	state.Tailnet = func(context.Context) (bool, string) { return false, "" }
	if state.Ready(context.Background()) || !state.Live() {
		t.Fatal("tailnet down should clear readiness only")
	}
	state.Fail()
	if state.Live() {
		t.Fatal("failed state should not be live")
	}
}

func TestHTTPHandlers(t *testing.T) {
	state := &State{Tailnet: func(context.Context) (bool, string) { return true, "dns" }}
	state.AddListener()
	srv := &Server{state: state}
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	srv.health(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("health status %d", rr.Code)
	}
	var body statusBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Ready || body.Listeners != 1 || !body.Tailscale.Connected || body.Tailscale.Hostname != "dns" {
		t.Fatalf("%+v", body)
	}

	rr = httptest.NewRecorder()
	srv.ready(rr, httptest.NewRequest(http.MethodGet, "/ready", nil))
	got, _ := io.ReadAll(rr.Body)
	if rr.Code != http.StatusOK || string(got) != "ready\n" {
		t.Fatalf("ready %d %q", rr.Code, got)
	}

	state.ShuttingDown()
	rr = httptest.NewRecorder()
	srv.health(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("shutdown health %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	srv.ready(rr, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("shutdown ready %d", rr.Code)
	}
}
