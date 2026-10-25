// terraform-provider-pulsegrid: Pulsegrid server monitoring as code.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/example-org/pulsegrid/terraform-provider-pulsegrid/internal/provider"
)

// Set by the release build.
var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "run with support for debuggers like delve")
	flag.Parse()
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/Example/pulsegrid",
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
