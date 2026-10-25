package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type checkResource struct{ client *Client }

func newCheckResource() resource.Resource { return &checkResource{} }

type checkModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Type            types.String `tfsdk:"type"`
	Target          types.String `tfsdk:"target"`
	Params          types.Map    `tfsdk:"params"`
	IntervalSeconds types.Int64  `tfsdk:"interval_seconds"`
	HostID          types.String `tfsdk:"host_id"`
	Tag             types.String `tfsdk:"tag"`
	OnProbes        types.Bool   `tfsdk:"on_probes"`
	ProbeRegions    types.List   `tfsdk:"probe_regions"`
	MinFailing      types.Int64  `tfsdk:"min_failing"`
	Enabled         types.Bool   `tfsdk:"enabled"`
}

type checkJSON struct {
	ID              string            `json:"id,omitempty"`
	Name            string            `json:"name"`
	Type            string            `json:"type"`
	Target          string            `json:"target"`
	Params          map[string]string `json:"params"`
	IntervalSeconds int64             `json:"interval_seconds"`
	HostID          *string           `json:"host_id"`
	Tag             *string           `json:"tag"`
	OnProbes        bool              `json:"on_probes"`
	ProbeRegions    []string          `json:"probe_regions"`
	MinFailing      int64             `json:"min_failing"`
	Enabled         bool              `json:"enabled"`
	// Terraform manages alert rules itself (pulsegrid_alert_rule, kind = "check").
	Alert *bool `json:"alert,omitempty"`
}

func (r *checkResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_check"
}

func (r *checkResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A check: a port, URL, certificate, DNS record, file or log pattern, run by the agent on " +
			"your servers, or (on_probes) an uptime check run from Pulsegrid's probe locations. " +
			"Alert on it with a pulsegrid_alert_rule of kind \"check\" whose target is this check's id.",
		Attributes: map[string]schema.Attribute{
			"id":   schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name": schema.StringAttribute{Required: true},
			"type": schema.StringAttribute{Required: true, Description: "tcp, http, tls, dns, ping, file or log.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"target": schema.StringAttribute{Required: true, Description: "host:port, URL, hostname or file path, depending on type."},
			"params": schema.MapAttribute{ElementType: types.StringType, Optional: true, Computed: true,
				Default:     mapdefault.StaticValue(types.MapValueMust(types.StringType, map[string]attr.Value{})),
				Description: "Type-specific settings, e.g. expected_status, keyword, max_response_ms, cert_days, pattern."},
			"interval_seconds": schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(60)},
			"host_id":          schema.StringAttribute{Optional: true, Description: "Run on this server."},
			"tag":              schema.StringAttribute{Optional: true, Description: "Run on every server with this tag."},
			"on_probes": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "Run from the public probes (uptime checks) instead of your servers."},
			"probe_regions": schema.ListAttribute{ElementType: types.StringType, Optional: true, Computed: true,
				Default:     listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
				Description: "Probe locations to use; empty means all."},
			"min_failing": schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(1),
				Description: "Uptime checks: how many locations must fail before the check counts as down."},
			"enabled": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
		},
	}
}

func (r *checkResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (m *checkModel) toJSON(ctx context.Context, diags *diag.Diagnostics) checkJSON {
	return checkJSON{
		Name: m.Name.ValueString(), Type: m.Type.ValueString(), Target: m.Target.ValueString(),
		Params: stringMap(ctx, m.Params, diags), IntervalSeconds: m.IntervalSeconds.ValueInt64(),
		HostID: strPtr(m.HostID), Tag: strPtr(m.Tag), OnProbes: m.OnProbes.ValueBool(),
		ProbeRegions: stringList(ctx, m.ProbeRegions, diags), MinFailing: m.MinFailing.ValueInt64(),
		Enabled: m.Enabled.ValueBool(),
	}
}

func (m *checkModel) fromJSON(j checkJSON) {
	m.ID = types.StringValue(j.ID)
	m.Name, m.Type, m.Target = types.StringValue(j.Name), types.StringValue(j.Type), types.StringValue(j.Target)
	m.Params = mapValue(j.Params)
	m.IntervalSeconds = types.Int64Value(j.IntervalSeconds)
	m.HostID, m.Tag = strValue(j.HostID), strValue(j.Tag)
	m.OnProbes = types.BoolValue(j.OnProbes)
	m.ProbeRegions = listValue(j.ProbeRegions)
	m.MinFailing = types.Int64Value(j.MinFailing)
	m.Enabled = types.BoolValue(j.Enabled)
}

func (r *checkResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan checkModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	body := plan.toJSON(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	noAlert := false
	body.Alert = &noAlert
	var out checkJSON
	if err := r.client.do(ctx, "POST", "/v1/checks", body, &out); err != nil {
		resp.Diagnostics.AddError("Creating check failed", err.Error())
		return
	}
	plan.fromJSON(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *checkResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state checkModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	var out checkJSON
	err := r.client.do(ctx, "GET", "/v1/checks/"+state.ID.ValueString(), nil, &out)
	if readGone(ctx, err, resp) {
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading check failed", err.Error())
		return
	}
	state.fromJSON(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *checkResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state checkModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	body := plan.toJSON(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var out checkJSON
	if err := r.client.do(ctx, "PUT", "/v1/checks/"+state.ID.ValueString(), body, &out); err != nil {
		resp.Diagnostics.AddError("Updating check failed", err.Error())
		return
	}
	plan.fromJSON(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *checkResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state checkModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if err := r.client.do(ctx, "DELETE", "/v1/checks/"+state.ID.ValueString(), nil, nil); err != nil && err != errNotFound {
		resp.Diagnostics.AddError("Deleting check failed", err.Error())
	}
}

func (r *checkResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
