// terraform-provider-sentinel: Sentinel server monitoring as code.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/AlzyWelzy/pulsegrid-beyond/terraform-provider-sentinel/internal/provider"
)

// Set by the release build.
var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "run with support for debuggers like delve")
	flag.Parse()
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/alzywelzy/sentinel",
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
