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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type alertRuleResource struct{ client *Client }

func newAlertRuleResource() resource.Resource { return &alertRuleResource{} }

type escalationModel struct {
	DelayMinutes types.Int64 `tfsdk:"delay_minutes"`
	ChannelIDs   types.List  `tfsdk:"channel_ids"`
}

var escalationType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"delay_minutes": types.Int64Type,
	"channel_ids":   types.ListType{ElemType: types.StringType},
}}

type alertRuleModel struct {
	ID                types.String  `tfsdk:"id"`
	Name              types.String  `tfsdk:"name"`
	Kind              types.String  `tfsdk:"kind"`
	Metric            types.String  `tfsdk:"metric"`
	Operator          types.String  `tfsdk:"operator"`
	Threshold         types.Float64 `tfsdk:"threshold"`
	Target            types.String  `tfsdk:"target"`
	DurationSeconds   types.Int64   `tfsdk:"duration_seconds"`
	HostID            types.String  `tfsdk:"host_id"`
	Tag               types.String  `tfsdk:"tag"`
	ChannelIDs        types.List    `tfsdk:"channel_ids"`
	Escalations       types.List    `tfsdk:"escalations"`
	Enabled           types.Bool    `tfsdk:"enabled"`
	Aggregation       types.String  `tfsdk:"aggregation"`
	WindowSeconds     types.Int64   `tfsdk:"window_seconds"`
	RecoveryThreshold types.Float64 `tfsdk:"recovery_threshold"`
	Severity          types.String  `tfsdk:"severity"`
	ActionName        types.String  `tfsdk:"action_name"`
	Labels            types.Map     `tfsdk:"labels"`
	Description       types.String  `tfsdk:"description"`
}

type escalationJSON struct {
	DelayMinutes int64    `json:"delay_minutes"`
	ChannelIDs   []string `json:"channel_ids"`
}

type alertRuleJSON struct {
	ID                string            `json:"id,omitempty"`
	Name              string            `json:"name"`
	Kind              string            `json:"kind"`
	Metric            *string           `json:"metric"`
	Operator          *string           `json:"operator"`
	Threshold         *float64          `json:"threshold"`
	Target            *string           `json:"target"`
	DurationSeconds   int64             `json:"duration_seconds"`
	HostID            *string           `json:"host_id"`
	Tag               *string           `json:"tag"`
	ChannelIDs        []string          `json:"channel_ids"`
	Escalations       []escalationJSON  `json:"escalations"`
	Enabled           bool              `json:"enabled"`
	Aggregation       string            `json:"aggregation"`
	WindowSeconds     int64             `json:"window_seconds"`
	RecoveryThreshold *float64          `json:"recovery_threshold"`
	Severity          string            `json:"severity"`
	ActionName        *string           `json:"action_name"`
	Labels            map[string]string `json:"labels"`
	Description       *string           `json:"description"`
}

func (r *alertRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_alert_rule"
}

func (r *alertRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An alert rule: when it fires, Sentinel opens an incident and notifies contacts.",
		Attributes: map[string]schema.Attribute{
			"id":   schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name": schema.StringAttribute{Required: true},
			"kind": schema.StringAttribute{Required: true,
				Description: "metric, host_down, process_down, service_down, container_down, plugin_down, custom, check, anomaly or forecast."},
			"metric": schema.StringAttribute{Optional: true,
				Description: "metric, anomaly and forecast rules: cpu, memory, swap, disk, inodes, load1, load5, load15, iowait, steal, disk_busy, net_in, net_out."},
			"operator":  schema.StringAttribute{Optional: true, Description: "> or < (metric and custom rules)."},
			"threshold": schema.Float64Attribute{Optional: true, Description: "Fires past this value; for anomaly, standard deviations; for forecast, hours."},
			"target": schema.StringAttribute{Optional: true,
				Description: "process/service/container/plugin name, custom metric name, or (check rules) the check id."},
			"duration_seconds": schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(300),
				Description: "How long the condition must hold before the rule fires."},
			"host_id": schema.StringAttribute{Optional: true, Description: "One server. Omit host_id and tag for every server."},
			"tag":     schema.StringAttribute{Optional: true, Description: "Every server with this tag, including ones added later."},
			"channel_ids": schema.ListAttribute{ElementType: types.StringType, Optional: true, Computed: true,
				Default:     listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
				Description: "Contacts to notify; empty means the account's default contacts."},
			"escalations": schema.ListNestedAttribute{Optional: true, Computed: true,
				Default:     listdefault.StaticValue(types.ListValueMust(escalationType, []attr.Value{})),
				Description: "Notify more contacts if the incident is still open (and not acknowledged) after a delay.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"delay_minutes": schema.Int64Attribute{Required: true},
					"channel_ids":   schema.ListAttribute{ElementType: types.StringType, Required: true},
				}},
			},
			"enabled": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"aggregation": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("last"),
				Description: "metric and custom rules: last, avg, max or min over window_seconds."},
			"window_seconds":     schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(300)},
			"recovery_threshold": schema.Float64Attribute{Optional: true, Description: "Resolves only once past this value (hysteresis)."},
			"severity": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("critical"),
				Description: "critical, warning or info."},
			"action_name": schema.StringAttribute{Optional: true,
				Description: "An action allowed in the server's actions.conf, run when the rule fires."},
			"labels": schema.MapAttribute{ElementType: types.StringType, Optional: true, Computed: true,
				Default:     mapdefault.StaticValue(types.MapValueMust(types.StringType, map[string]attr.Value{})),
				Description: "custom rules: label filters."},
			"description": schema.StringAttribute{Optional: true, Description: "Runbook text included in alerts."},
		},
	}
}

func (r *alertRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (m *alertRuleModel) toJSON(ctx context.Context, diags *diag.Diagnostics) alertRuleJSON {
	var esc []escalationModel
	if !m.Escalations.IsNull() && !m.Escalations.IsUnknown() {
		diags.Append(m.Escalations.ElementsAs(ctx, &esc, false)...)
	}
	steps := []escalationJSON{}
	for _, e := range esc {
		steps = append(steps, escalationJSON{DelayMinutes: e.DelayMinutes.ValueInt64(), ChannelIDs: stringList(ctx, e.ChannelIDs, diags)})
	}
	return alertRuleJSON{
		Name: m.Name.ValueString(), Kind: m.Kind.ValueString(),
		Metric: strPtr(m.Metric), Operator: strPtr(m.Operator), Threshold: floatPtr(m.Threshold),
		Target: strPtr(m.Target), DurationSeconds: m.DurationSeconds.ValueInt64(),
		HostID: strPtr(m.HostID), Tag: strPtr(m.Tag),
		ChannelIDs: stringList(ctx, m.ChannelIDs, diags), Escalations: steps,
		Enabled: m.Enabled.ValueBool(), Aggregation: m.Aggregation.ValueString(),
		WindowSeconds: m.WindowSeconds.ValueInt64(), RecoveryThreshold: floatPtr(m.RecoveryThreshold),
		Severity: m.Severity.ValueString(), ActionName: strPtr(m.ActionName),
		Labels: stringMap(ctx, m.Labels, diags), Description: strPtr(m.Description),
	}
}

func (m *alertRuleModel) fromJSON(j alertRuleJSON) {
	m.ID = types.StringValue(j.ID)
	m.Name = types.StringValue(j.Name)
	m.Kind = types.StringValue(j.Kind)
	m.Metric, m.Operator, m.Threshold = strValue(j.Metric), strValue(j.Operator), floatValue(j.Threshold)
	m.Target = strValue(j.Target)
	m.DurationSeconds = types.Int64Value(j.DurationSeconds)
	m.HostID, m.Tag = strValue(j.HostID), strValue(j.Tag)
	m.ChannelIDs = listValue(j.ChannelIDs)
	steps := make([]attr.Value, len(j.Escalations))
	for i, e := range j.Escalations {
		steps[i] = types.ObjectValueMust(escalationType.AttrTypes, map[string]attr.Value{
			"delay_minutes": types.Int64Value(e.DelayMinutes),
			"channel_ids":   listValue(e.ChannelIDs),
		})
	}
	m.Escalations = types.ListValueMust(escalationType, steps)
	m.Enabled = types.BoolValue(j.Enabled)
	m.Aggregation = types.StringValue(j.Aggregation)
	m.WindowSeconds = types.Int64Value(j.WindowSeconds)
	m.RecoveryThreshold = floatValue(j.RecoveryThreshold)
	m.Severity = types.StringValue(j.Severity)
	m.ActionName = strValue(j.ActionName)
	m.Labels = mapValue(j.Labels)
	m.Description = strValue(j.Description)
}

func (r *alertRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan alertRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	body := plan.toJSON(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var out alertRuleJSON
	if err := r.client.do(ctx, "POST", "/v1/alert-rules", body, &out); err != nil {
		resp.Diagnostics.AddError("Creating alert rule failed", err.Error())
		return
	}
	plan.fromJSON(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *alertRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state alertRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	var out alertRuleJSON
	err := r.client.do(ctx, "GET", "/v1/alert-rules/"+state.ID.ValueString(), nil, &out)
	if readGone(ctx, err, resp) {
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading alert rule failed", err.Error())
		return
	}
	state.fromJSON(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *alertRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state alertRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	body := plan.toJSON(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var out alertRuleJSON
	if err := r.client.do(ctx, "PUT", "/v1/alert-rules/"+state.ID.ValueString(), body, &out); err != nil {
		resp.Diagnostics.AddError("Updating alert rule failed", err.Error())
		return
	}
	plan.fromJSON(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *alertRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state alertRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if err := r.client.do(ctx, "DELETE", "/v1/alert-rules/"+state.ID.ValueString(), nil, nil); err != nil && err != errNotFound {
		resp.Diagnostics.AddError("Deleting alert rule failed", err.Error())
	}
}

func (r *alertRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
