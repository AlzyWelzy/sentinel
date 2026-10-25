package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type installKeyResource struct{ client *Client }

func newInstallKeyResource() resource.Resource { return &installKeyResource{} }

type installKeyModel struct {
	ID                    types.String `tfsdk:"id"`
	Name                  types.String `tfsdk:"name"`
	Tags                  types.List   `tfsdk:"tags"`
	Key                   types.String `tfsdk:"key"`
	InstallCommand        types.String `tfsdk:"install_command"`
	InstallCommandWindows types.String `tfsdk:"install_command_windows"`
	CloudInit             types.String `tfsdk:"cloud_init"`
}

type installKeyJSON struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	Key                   string   `json:"key"`
	InstallCommand        string   `json:"install_command"`
	InstallCommandWindows string   `json:"install_command_windows"`
	CloudInit             string   `json:"cloud_init"`
	RevokedAt             *string  `json:"revoked_at"`
}

func (r *installKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_install_key"
}

func (r *installKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "An agent install key, for installing the agent from your own automation (cloud-init, Ansible). " +
			"Destroying it revokes the key; servers already installed keep reporting.",
		Attributes: map[string]schema.Attribute{
			"id":   schema.StringAttribute{Computed: true, PlanModifiers: keep},
			"name": schema.StringAttribute{Required: true, PlanModifiers: replace},
			"tags": schema.ListAttribute{ElementType: types.StringType, Optional: true, Computed: true,
				Default:       listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
				PlanModifiers: []planmodifier.List{listplanmodifier.RequiresReplace()},
				Description:   "Tags added to servers installed with this key."},
			"key":                     schema.StringAttribute{Computed: true, Sensitive: true, PlanModifiers: keep},
			"install_command":         schema.StringAttribute{Computed: true, Sensitive: true, PlanModifiers: keep},
			"install_command_windows": schema.StringAttribute{Computed: true, Sensitive: true, PlanModifiers: keep},
			"cloud_init":              schema.StringAttribute{Computed: true, Sensitive: true, PlanModifiers: keep},
		},
	}
}

func (r *installKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *installKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan installKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	tags := stringList(ctx, plan.Tags, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var out installKeyJSON
	if err := r.client.do(ctx, "POST", "/v1/agent-keys", map[string]any{"name": plan.Name.ValueString(), "tags": tags}, &out); err != nil {
		resp.Diagnostics.AddError("Creating install key failed", err.Error())
		return
	}
	plan.ID = types.StringValue(out.ID)
	plan.Key = types.StringValue(out.Key)
	plan.InstallCommand = types.StringValue(out.InstallCommand)
	plan.InstallCommandWindows = types.StringValue(out.InstallCommandWindows)
	plan.CloudInit = types.StringValue(out.CloudInit)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read keeps the secret and tags from state (the API shows the key only at
// creation, and tags live only in the install command) and drops the
// resource if the key was revoked or deleted elsewhere.
func (r *installKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state installKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	var keys []installKeyJSON
	if err := r.client.do(ctx, "GET", "/v1/agent-keys", nil, &keys); err != nil {
		resp.Diagnostics.AddError("Reading install keys failed", err.Error())
		return
	}
	for _, k := range keys {
		if k.ID == state.ID.ValueString() && k.RevokedAt == nil {
			state.Name = types.StringValue(k.Name)
			resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
			return
		}
	}
	resp.State.RemoveResource(ctx)
}

func (r *installKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Every attribute forces replacement; nothing to update in place.
	var plan installKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *installKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state installKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if err := r.client.do(ctx, "DELETE", "/v1/agent-keys/"+state.ID.ValueString(), nil, nil); err != nil && err != errNotFound {
		resp.Diagnostics.AddError("Revoking install key failed", err.Error())
	}
}

func (r *installKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
