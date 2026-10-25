package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type statusPageResource struct{ client *Client }

func newStatusPageResource() resource.Resource { return &statusPageResource{} }

type statusItemModel struct {
	Label   types.String `tfsdk:"label"`
	HostID  types.String `tfsdk:"host_id"`
	CheckID types.String `tfsdk:"check_id"`
}

var statusItemType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"label": types.StringType, "host_id": types.StringType, "check_id": types.StringType,
}}

type statusPageModel struct {
	ID          types.String `tfsdk:"id"`
	Slug        types.String `tfsdk:"slug"`
	Title       types.String `tfsdk:"title"`
	Description types.String `tfsdk:"description"`
	ShowValues  types.Bool   `tfsdk:"show_values"`
	Published   types.Bool   `tfsdk:"published"`
	Items       types.List   `tfsdk:"items"`
}

type statusItemJSON struct {
	Label   string  `json:"label"`
	HostID  *string `json:"host_id"`
	CheckID *string `json:"check_id"`
}

type statusPageJSON struct {
	ID          string           `json:"id,omitempty"`
	Slug        string           `json:"slug"`
	Title       string           `json:"title"`
	Description *string          `json:"description"`
	ShowValues  bool             `json:"show_values"`
	Published   bool             `json:"published"`
	Items       []statusItemJSON `json:"items"`
}

func (r *statusPageResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_status_page"
}

func (r *statusPageResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A public status page. Visitors see your labels, up/down, 90-day uptime and incidents; " +
			"never hostnames, addresses or check targets.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"slug":        schema.StringAttribute{Required: true, Description: "The page's address: lowercase letters, digits and dashes."},
			"title":       schema.StringAttribute{Required: true},
			"description": schema.StringAttribute{Optional: true},
			"show_values": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true),
				Description: "Show uptime percentages and response times."},
			"published": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true)},
			"items": schema.ListNestedAttribute{Optional: true, Computed: true,
				Default:     listdefault.StaticValue(types.ListValueMust(statusItemType, []attr.Value{})),
				Description: "What the page shows, in order: each a server (host_id) or a check (check_id).",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"label":    schema.StringAttribute{Required: true},
					"host_id":  schema.StringAttribute{Optional: true},
					"check_id": schema.StringAttribute{Optional: true},
				}},
			},
		},
	}
}

func (r *statusPageResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (m *statusPageModel) toJSON(ctx context.Context, diags *diag.Diagnostics) statusPageJSON {
	var items []statusItemModel
	if !m.Items.IsNull() && !m.Items.IsUnknown() {
		diags.Append(m.Items.ElementsAs(ctx, &items, false)...)
	}
	out := statusPageJSON{
		Slug: m.Slug.ValueString(), Title: m.Title.ValueString(), Description: strPtr(m.Description),
		ShowValues: m.ShowValues.ValueBool(), Published: m.Published.ValueBool(), Items: []statusItemJSON{},
	}
	for _, it := range items {
		out.Items = append(out.Items, statusItemJSON{Label: it.Label.ValueString(), HostID: strPtr(it.HostID), CheckID: strPtr(it.CheckID)})
	}
	return out
}

func (m *statusPageModel) fromJSON(j statusPageJSON) {
	m.ID, m.Slug, m.Title = types.StringValue(j.ID), types.StringValue(j.Slug), types.StringValue(j.Title)
	m.Description = strValue(j.Description)
	m.ShowValues, m.Published = types.BoolValue(j.ShowValues), types.BoolValue(j.Published)
	items := make([]attr.Value, len(j.Items))
	for i, it := range j.Items {
		items[i] = types.ObjectValueMust(statusItemType.AttrTypes, map[string]attr.Value{
			"label": types.StringValue(it.Label), "host_id": strValue(it.HostID), "check_id": strValue(it.CheckID),
		})
	}
	m.Items = types.ListValueMust(statusItemType, items)
}

func (r *statusPageResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan statusPageModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	body := plan.toJSON(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var out statusPageJSON
	if err := r.client.do(ctx, "POST", "/v1/status-pages", body, &out); err != nil {
		resp.Diagnostics.AddError("Creating status page failed", err.Error())
		return
	}
	plan.fromJSON(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *statusPageResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state statusPageModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	var out statusPageJSON
	err := r.client.do(ctx, "GET", "/v1/status-pages/"+state.ID.ValueString(), nil, &out)
	if readGone(ctx, err, resp) {
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading status page failed", err.Error())
		return
	}
	state.fromJSON(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *statusPageResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state statusPageModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	body := plan.toJSON(ctx, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var out statusPageJSON
	if err := r.client.do(ctx, "PUT", "/v1/status-pages/"+state.ID.ValueString(), body, &out); err != nil {
		resp.Diagnostics.AddError("Updating status page failed", err.Error())
		return
	}
	plan.fromJSON(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *statusPageResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state statusPageModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if err := r.client.do(ctx, "DELETE", "/v1/status-pages/"+state.ID.ValueString(), nil, nil); err != nil && err != errNotFound {
		resp.Diagnostics.AddError("Deleting status page failed", err.Error())
	}
}

func (r *statusPageResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
