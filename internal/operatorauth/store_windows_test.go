//go:build windows

package operatorauth_test

import (
	"reflect"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/operatorauth"
)

func TestWindowsStoreReplaceUsesPortableDirectoryDurability(t *testing.T) {
	store := operatorauth.NewStore(t.TempDir())
	want := operatorauth.Credential{ID: "AQI", PublicKey: "public", Algorithm: -7}
	if err := store.Replace([]operatorauth.Credential{want}); err != nil {
		t.Fatal(err)
	}
	got, err := store.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []operatorauth.Credential{want}) {
		t.Fatalf("Credentials() = %+v, want %+v", got, []operatorauth.Credential{want})
	}
}
