// Command testregistry serves the meles EICAR test images on a fixed
// address, for trying the web UI locally:
//
//	go run ./hack/testregistry -listen 127.0.0.1:5055
//	meles server --insecure-registry ...   # then scan 127.0.0.1:5055/selftest/eicar-whiteout:latest
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"git.itknecht.de/sugras/meles/internal/testimage"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:5055", "listen address")
	flag.Parse()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	go http.Serve(ln, registry.New(registry.Logger(log.New(io.Discard, "", 0))))

	for _, c := range testimage.Cases() {
		img, err := testimage.Build(c.Layers)
		if err != nil {
			log.Fatal(err)
		}
		ref := fmt.Sprintf("%s/selftest/%s:latest", ln.Addr(), c.Name)
		r, err := name.ParseReference(ref, name.Insecure)
		if err != nil {
			log.Fatal(err)
		}
		if err := remote.Write(r, img); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintln(os.Stdout, ref)
	}
	select {}
}
