// nameserver runs CoreDNS with zone-file serving and IHLE additional processing.
package main

import (
	"strconv"

	"github.com/adem-wg/adem-proto/plugin/ihle"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
	"github.com/coredns/coredns/plugin"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/file"
	_ "github.com/coredns/coredns/plugin/log"
	_ "github.com/coredns/coredns/plugin/root"
)

func init() { plugin.Register("ihle", setup) }

func setup(c *caddy.Controller) error {
	h := ihle.IHLE{}
	for c.Next() {
		args := c.RemainingArgs()
		if len(args) != 1 || c.NextBlock() {
			return plugin.Error("ihle", c.ArgErr())
		}
		if value, err := strconv.ParseUint(args[0], 10, 16); err != nil || value == 0 {
			return plugin.Error("ihle", c.Err("expected a nonzero numeric IHLE RR type"))
		} else {
			h.TypeNum = uint16(value)
		}
	}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		h.Next = next
		return h
	})
	return nil
}

func main() {
	dnsserver.Directives = []string{"root", "bind", "log", "errors", "ihle", "file"}
	coremain.Run()
}
