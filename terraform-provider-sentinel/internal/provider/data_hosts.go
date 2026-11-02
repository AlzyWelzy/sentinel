package provider

import (
	"context"
	"net/url"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type hostsDataSource struct{ client *Client }

func newHostsDataSource() datasource.DataSource { return &hostsDataSource{} }

var hostType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"id": types.StringType, "hostname": types.StringType, "tags": types.ListType{ElemType: types.StringType},
	"online": types.BoolType, "platform": types.StringType, "agent_version": types.StringType,
}}

type hostsModel struct {
	Tag      types.String `tfsdk:"tag"`
	Hostname types.String `tfsdk:"hostname"`
	Hosts    types.List   `tfsdk:"hosts"`
}

type hostJSON struct {
	ID           string   `json:"id"`
	Hostname     string   `json:"hostname"`
	Tags         []string `json:"tags"`
	Online       bool     `json:"online"`
	Platform     *string  `json:"platform"`
	AgentVersion *string  `json:"agent_version"`
}

func (d *hostsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_hosts"
}

func (d *hostsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Servers reporting to Sentinel, optionally filtered by tag or hostname.",
		Attributes: map[string]schema.Attribute{
			"tag":      schema.StringAttribute{Optional: true},
			"hostname": schema.StringAttribute{Optional: true, Description: "Exact hostname."},
			"hosts": schema.ListNestedAttribute{Computed: true, NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
				"id":            schema.StringAttribute{Computed: true},
				"hostname":      schema.StringAttribute{Computed: true},
				"tags":          schema.ListAttribute{ElementType: types.StringType, Computed: true},
				"online":        schema.BoolAttribute{Computed: true},
				"platform":      schema.StringAttribute{Computed: true},
				"agent_version": schema.StringAttribute{Computed: true},
			}}},
		},
	}
}

func (d *hostsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *hostsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg hostsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	path := "/v1/hosts"
	if tag := cfg.Tag.ValueString(); tag != "" {
		path += "?tag=" + url.QueryEscape(tag)
	}
	var hosts []hostJSON
	if err := d.client.do(ctx, "GET", path, nil, &hosts); err != nil {
		resp.Diagnostics.AddError("Listing hosts failed", err.Error())
		return
	}
	vals := []attr.Value{}
	for _, h := range hosts {
		if name := cfg.Hostname.ValueString(); name != "" && h.Hostname != name {
			continue
		}
		if tag := cfg.Tag.ValueString(); tag != "" && !slices.Contains(h.Tags, tag) {
			continue
		}
		vals = append(vals, types.ObjectValueMust(hostType.AttrTypes, map[string]attr.Value{
			"id": types.StringValue(h.ID), "hostname": types.StringValue(h.Hostname), "tags": listValue(h.Tags),
			"online": types.BoolValue(h.Online), "platform": strValue(h.Platform), "agent_version": strValue(h.AgentVersion),
		}))
	}
	cfg.Hosts = types.ListValueMust(hostType, vals)
	resp.Diagnostics.Append(resp.State.Set(ctx, cfg)...)
}
