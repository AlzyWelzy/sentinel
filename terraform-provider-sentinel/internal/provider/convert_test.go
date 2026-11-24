package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestKeptParams(t *testing.T) {
	prior := types.MapValueMust(types.StringType, map[string]attr.Value{
		"keyword":  types.StringValue("Sign in"),
		"password": types.StringValue("hunter2"),
	})
	api := map[string]string{"keyword": "Sign in", "password": paramMask, "method": "GET"}
	got := keptParams(prior, api)
	if len(got) != 2 || got["password"] != "hunter2" || got["keyword"] != "Sign in" {
		t.Fatalf("got %v", got)
	}
	if all := keptParams(types.MapNull(types.StringType), api); len(all) != 3 {
		t.Fatalf("an import takes every param, got %v", all)
	}
}
