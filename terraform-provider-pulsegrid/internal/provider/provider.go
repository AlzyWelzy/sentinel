// Package provider is the Terraform provider for Pulsegrid server monitoring:
// alert rules, checks, maintenance windows, status pages and install keys as
// code, using a Pulsegrid API token.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type pulsegridProvider struct{ version string }

type providerModel struct {
	APIURL types.String `tfsdk:"api_url"`
	Token  types.String `tfsdk:"token"`
}

// New returns the provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &pulsegridProvider{version: version} }
}

func (p *pulsegridProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pulsegrid"
	resp.Version = p.version
}

func (p *pulsegridProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage Pulsegrid server monitoring as code. Authenticate with an API token " +
			"(Monitoring → Servers → API in the console) that is not read-only.",
		Attributes: map[string]schema.Attribute{
			"api_url": schema.StringAttribute{
				Optional:    true,
				Description: "Pulsegrid API base URL, e.g. https://<console host>/api/pulsegrid. Defaults to $PULSEGRID_API_URL.",
			},
			"token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "API token (pgt_…). Defaults to $PULSEGRID_TOKEN.",
			},
		},
	}
}

func (p *pulsegridProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	url := firstSet(cfg.APIURL.ValueString(), os.Getenv("PULSEGRID_API_URL"))
	token := firstSet(cfg.Token.ValueString(), os.Getenv("PULSEGRID_TOKEN"))
	if url == "" {
		resp.Diagnostics.AddError("Missing API URL",
			"Set api_url in the provider block or PULSEGRID_API_URL, e.g. https://<console host>/api/pulsegrid.")
		return
	}
	if token == "" {
		resp.Diagnostics.AddError("Missing API token",
			"Set token in the provider block or PULSEGRID_TOKEN. Create one under Monitoring → Servers → API, with read-only off.")
		return
	}
	client := newClient(url, token, p.version)
	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *pulsegridProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newAlertRuleResource,
		newCheckResource,
		newMaintenanceWindowResource,
		newStatusPageResource,
		newInstallKeyResource,
	}
}

func (p *pulsegridProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newHostsDataSource}
}

func firstSet(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
