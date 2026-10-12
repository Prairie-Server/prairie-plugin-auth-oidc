package provider

import (
	"context"
	"testing"

	pluginv1 "github.com/prairie-server/prairie-plugin-sdk/pkg/pluginproto/prairie/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestParseConfigSkipsUnnamedEntries(t *testing.T) {
	t.Parallel()
	value, err := structpb.NewStruct(map[string]any{"issuer_url": "https://idp.example"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig([]*pluginv1.ConfigEntry{nil, {Value: value}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "" {
		t.Fatalf("an entry without a key must be ignored, got issuer %q", cfg.Issuer)
	}
}

func TestConfigFieldTypes(t *testing.T) {
	t.Parallel()
	if got, err := boolField(map[string]any{"f": "false"}, "k", "f"); err != nil || got {
		t.Fatalf(`"false" = %v, %v`, got, err)
	}
	if got, err := boolField(map[string]any{"f": " TRUE "}, "k", "f"); err != nil || !got {
		t.Fatalf(`"TRUE" = %v, %v`, got, err)
	}
	if _, err := boolField(map[string]any{"f": "maybe"}, "k", "f"); err == nil {
		t.Fatal("an unrecognised boolean string must be refused")
	}
	if _, err := listField(map[string]any{"f": []any{"a", 3.0}}, "k", "f"); err == nil {
		t.Fatal("a list with a non-string must be refused")
	}
	if _, err := listField(map[string]any{"f": 3.0}, "k", "f"); err == nil {
		t.Fatal("a number is not a list")
	}
}

func TestClaimHelpersRejectOddInput(t *testing.T) {
	t.Parallel()
	if value, ok := lookupClaim(map[string]any{"a": "text"}, "a.b"); ok || value != nil {
		t.Fatalf("walking into a string = %v, %v", value, ok)
	}
	if !asciiEqualFold("Prairie-Admins", "prairie-admins") || !asciiEqualFold("a", "A") {
		t.Fatal("ASCII case must fold on either side")
	}
	if _, err := externalSubject(Config{}, map[string]any{"sub": "u"}); err == nil {
		t.Fatal("a token without iss must not yield an account key")
	}
	if isMicrosoftIssuer("://not a url") {
		t.Fatal("an unparsable issuer is not Microsoft's")
	}
}

func TestTestConnectionStopsOnBadSettings(t *testing.T) {
	t.Parallel()
	for name, connection := range map[string]map[string]any{
		"wrong type":      {"issuer_url": 5.0},
		"insecure issuer": {"issuer_url": "http://idp.example", "client_id": "c"},
	} {
		resp, err := New(nil).TestConnection(context.Background(), &pluginv1.AuthTestConnectionRequest{Config: settings{connection: connection}.entries(t)})
		if err != nil {
			t.Fatal(err)
		}
		steps := resp.GetSteps()
		if resp.GetOk() || len(steps) == 0 || steps[len(steps)-1].GetId() != stepSettings || steps[len(steps)-1].GetOk() {
			t.Errorf("%s: ok=%v steps=%v", name, resp.GetOk(), steps)
		}
	}
}
