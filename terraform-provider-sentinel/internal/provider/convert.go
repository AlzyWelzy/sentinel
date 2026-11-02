package provider

import (
	"context"
	"errors"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Optional values travel to the API as JSON null when unset.

func strPtr(v types.String) *string {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	s := v.ValueString()
	return &s
}

func floatPtr(v types.Float64) *float64 {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	f := v.ValueFloat64()
	return &f
}

func intPtr(v types.Int64) *int64 {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	i := v.ValueInt64()
	return &i
}

func strValue(p *string) types.String {
	if p == nil {
		return types.StringNull()
	}
	return types.StringValue(*p)
}

func floatValue(p *float64) types.Float64 {
	if p == nil {
		return types.Float64Null()
	}
	return types.Float64Value(*p)
}

func intValue(p *int64) types.Int64 {
	if p == nil {
		return types.Int64Null()
	}
	return types.Int64Value(*p)
}

func stringList(ctx context.Context, v types.List, diags *diag.Diagnostics) []string {
	out := []string{}
	if v.IsNull() || v.IsUnknown() {
		return out
	}
	diags.Append(v.ElementsAs(ctx, &out, false)...)
	return out
}

func stringMap(ctx context.Context, v types.Map, diags *diag.Diagnostics) map[string]string {
	out := map[string]string{}
	if v.IsNull() || v.IsUnknown() {
		return out
	}
	diags.Append(v.ElementsAs(ctx, &out, false)...)
	return out
}

func listValue(items []string) types.List {
	vals := make([]attr.Value, len(items))
	for i, s := range items {
		vals[i] = types.StringValue(s)
	}
	return types.ListValueMust(types.StringType, vals)
}

func int64ListValue(items []int64) types.List {
	vals := make([]attr.Value, len(items))
	for i, n := range items {
		vals[i] = types.Int64Value(n)
	}
	return types.ListValueMust(types.Int64Type, vals)
}

func mapValue(m map[string]string) types.Map {
	vals := make(map[string]attr.Value, len(m))
	for k, s := range m {
		vals[k] = types.StringValue(s)
	}
	return types.MapValueMust(types.StringType, vals)
}

// readGone handles an object deleted outside Terraform: drop it from state
// so the next plan recreates it.
func readGone(ctx context.Context, err error, resp *resource.ReadResponse) bool {
	if errors.Is(err, errNotFound) {
		resp.State.RemoveResource(ctx)
		return true
	}
	return false
}

// clientFrom pulls the API client out of ConfigureRequest.ProviderData.
func clientFrom(data any, diags *diag.Diagnostics) *Client {
	if data == nil {
		return nil
	}
	c, ok := data.(*Client)
	if !ok {
		diags.AddError("Unexpected provider data", "This is a bug in the provider.")
		return nil
	}
	return c
}
