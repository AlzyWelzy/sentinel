package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type maintenanceResource struct{ client *Client }

func newMaintenanceWindowResource() resource.Resource { return &maintenanceResource{} }

type maintenanceModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	HostID          types.String `tfsdk:"host_id"`
	Tag             types.String `tfsdk:"tag"`
	Schedule        types.String `tfsdk:"schedule"`
	StartsAt        types.String `tfsdk:"starts_at"`
	EndsAt          types.String `tfsdk:"ends_at"`
	Weekdays        types.List   `tfsdk:"weekdays"`
	StartTime       types.String `tfsdk:"start_time"`
	DurationMinutes types.Int64  `tfsdk:"duration_minutes"`
	Timezone        types.String `tfsdk:"timezone"`
	Enabled         types.Bool   `tfsdk:"enabled"`
}

type maintenanceJSON struct {
	ID              string  `json:"id,omitempty"`
	Name            string  `json:"name"`
	HostID          *string `json:"host_id"`
	Tag             *string `json:"tag"`
	Schedule        string  `json:"schedule"`
	StartsAt        *string `json:"starts_at"`
	EndsAt          *string `json:"ends_at"`
	Weekdays        []int64 `json:"weekdays"`
	StartTime       *string `json:"start_time"`
	DurationMinutes *int64  `json:"duration_minutes"`
	Timezone        string  `json:"timezone"`
	Enabled         bool    `json:"enabled"`
}

func (r *maintenanceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_maintenance_window"
}

func (r *maintenanceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A maintenance window: alerts for the servers it covers are held back while it's active.",
		Attributes: map[string]schema.Attribute{
			"id":        schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":      schema.StringAttribute{Required: true},
			"host_id":   schema.StringAttribute{Optional: true, Description: "One server. Omit host_id and tag for every server."},
			"tag":       schema.StringAttribute{Optional: true, Description: "Every server with this tag."},
			"schedule":  schema.StringAttribute{Required: true, Description: "once or weekly."},
			"starts_at": schema.StringAttribute{Optional: true, Description: "once: RFC 3339 start, e.g. 2026-11-01T22:00:00Z."},
			"ends_at":   schema.StringAttribute{Optional: true, Description: "once: RFC 3339 end."},
			"weekdays": schema.ListAttribute{ElementType: types.Int64Type, Optional: true,
				Description: "weekly: ISO weekdays, 1 = Monday … 7 = Sunday."},
			"start_time":       schema.StringAttribute{Optional: true, Description: "weekly: local start time, HH:MM."},
			"duration_minutes": schema.Int64Attribute{Optional: true, Description: "weekly: how long each window lasts."},
			"timezone": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("UTC"),
				Description: "IANA zone for start_time, e.g. Asia/Kolkata."},
			"enabled": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
		},
	}
}

func (r *maintenanceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (m *maintenanceModel) toJSON(ctx context.Context, diags *diag.Diagnostics) maintenanceJSON {
	var days []int64
	if !m.Weekdays.IsNull() && !m.Weekdays.IsUnknown() {
		diags.Append(m.Weekdays.ElementsAs(ctx, &days, false)...)
	}
	return maintenanceJSON{
		Name: m.Name.ValueString(), HostID: strPtr(m.HostID), Tag: strPtr(m.Tag),
		Schedule: m.Schedule.ValueString(), StartsAt: strPtr(m.StartsAt), EndsAt: strPtr(m.EndsAt),
		Weekdays: days, StartTime: strPtr(m.StartTime), DurationMinutes: intPtr(m.DurationMinutes),
		Timezone: m.Timezone.ValueString(), Enabled: m.Enabled.ValueBool(),
	}
}

// sameInstant keeps the configured spelling of a timestamp when the API
// returns the same moment written differently, so plans stay clean.
func sameInstant(configured types.String, got *string) types.String {
	if got == nil {
		return types.StringNull()
	}
	if !configured.IsNull() && !configured.IsUnknown() {
		a, errA := time.Parse(time.RFC3339, configured.ValueString())
		b, errB := time.Parse(time.RFC3339, *got)
		if errA == nil && errB == nil && a.Equal(b) {
			return configured
		}
	}
	return types.StringValue(*got)
}

func (m *maintenanceModel) fromJSON(j maintenanceJSON) {
	m.ID = types.StringValue(j.ID)
	m.Name = types.StringValue(j.Name)
	m.HostID, m.Tag = strValue(j.HostID), strValue(j.Tag)
	m.Schedule = types.StringValue(j.Schedule)
	m.StartsAt, m.EndsAt = sameInstant(m.StartsAt, j.StartsAt), sameInstant(m.EndsAt, j.EndsAt)
	if j.Weekdays == nil {
		m.Weekdays = types.ListNull(types.Int64Type)
	} else {
		m.Weekdays = int64ListValue(j.Weekdays)
	}
	m.StartTime = strValue(j.StartTime)
	m.DurationMinutes = intValue(j.DurationMinutes)
	m.Timezone = types.StringValue(j.Timezone)
	m.Enabled = types.BoolValue(j.Enabled)
}

func (r *maintenanceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan maintenanceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	body := plan.toJSON(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var out maintenanceJSON
	if err := r.client.do(ctx, "POST", "/v1/maintenance", body, &out); err != nil {
		resp.Diagnostics.AddError("Creating maintenance window failed", err.Error())
		return
	}
	plan.fromJSON(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *maintenanceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state maintenanceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	var out maintenanceJSON
	err := r.client.do(ctx, "GET", "/v1/maintenance/"+state.ID.ValueString(), nil, &out)
	if readGone(ctx, err, resp) {
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading maintenance window failed", err.Error())
		return
	}
	state.fromJSON(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *maintenanceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state maintenanceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	body := plan.toJSON(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var out maintenanceJSON
	if err := r.client.do(ctx, "PUT", "/v1/maintenance/"+state.ID.ValueString(), body, &out); err != nil {
		resp.Diagnostics.AddError("Updating maintenance window failed", err.Error())
		return
	}
	plan.fromJSON(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *maintenanceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state maintenanceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if err := r.client.do(ctx, "DELETE", "/v1/maintenance/"+state.ID.ValueString(), nil, nil); err != nil && err != errNotFound {
		resp.Diagnostics.AddError("Deleting maintenance window failed", err.Error())
	}
}

func (r *maintenanceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
