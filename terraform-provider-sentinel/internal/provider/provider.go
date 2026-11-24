// Package provider is the Terraform provider for Sentinel server monitoring:
// alert rules, checks, maintenance windows, status pages and install keys as
// code, using a Sentinel API token.
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

type sentinelProvider struct{ version string }

type providerModel struct {
	APIURL types.String `tfsdk:"api_url"`
	Token  types.String `tfsdk:"token"`
}

// New returns the provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &sentinelProvider{version: version} }
}

func (p *sentinelProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sentinel"
	resp.Version = p.version
}

func (p *sentinelProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage Sentinel server monitoring as code. Authenticate with an API token " +
			"(Monitoring → Servers → API in the console) that is not read-only.",
		Attributes: map[string]schema.Attribute{
			"api_url": schema.StringAttribute{
				Optional:    true,
				Description: "Sentinel API base URL. Defaults to $SENTINEL_API_URL, then https://sentinel.rajpoot.app/api.",
			},
			"token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "API token (pgt_…). Defaults to $SENTINEL_TOKEN.",
			},
		},
	}
}

func (p *sentinelProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	url := firstSet(cfg.APIURL.ValueString(), os.Getenv("SENTINEL_API_URL"), defaultAPIURL)
	token := firstSet(cfg.Token.ValueString(), os.Getenv("SENTINEL_TOKEN"))
	if url == "" {
		resp.Diagnostics.AddError("Missing API URL",
			"Set api_url in the provider block or SENTINEL_API_URL, e.g. "+defaultAPIURL+".")
		return
	}
	if token == "" {
		resp.Diagnostics.AddError("Missing API token",
			"Set token in the provider block or SENTINEL_TOKEN. Create one under Monitoring → Servers → API, with read-only off.")
		return
	}
	client := newClient(url, token, p.version)
	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *sentinelProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newAlertRuleResource,
		newCheckResource,
		newMaintenanceWindowResource,
		newStatusPageResource,
		newInstallKeyResource,
	}
}

func (p *sentinelProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newHostsDataSource}
}

// The hosted Sentinel; self-hosted installs set api_url.
const defaultAPIURL = "https://sentinel.rajpoot.app/api"

func firstSet(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
