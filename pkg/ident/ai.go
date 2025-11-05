package ident

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/adem-wg/adem-proto/pkg/util"
)

var ErrIllegalAI = errors.New("illegal asset identifier")
var ErrNoAddress = errors.New("no address component")
var ErrIllegalAddress = errors.New("illegal address component")
var ErrWildcard = errors.New("illegal usage of domain name wildcards")

type AI struct {
	domain   []string
	ipAddr   net.IP
	ipPrefix *net.IPNet
}

func joinDomain(labels []string) string {
	if len(labels) == 1 && labels[0] == "*" {
		return ""
	} else if len(labels) > 1 && labels[0] == "*" {
		return "." + strings.Join(labels[1:], ".")
	} else {
		return strings.Join(labels, ".")
	}
}

func (ai *AI) MoreGeneral(than *AI) bool {
	if ai.domain != nil {
		if len(than.domain) == 0 {
			return false
		}

		aiJoined := joinDomain(ai.domain)
		thanJoined := joinDomain(than.domain)
		if ai.domain[0] == "*" {
			return thanJoined == joinDomain(ai.domain[1:]) || strings.HasSuffix(thanJoined, aiJoined)
		} else {
			return thanJoined == aiJoined
		}
	} else if ai.ipAddr != nil {
		return ai.ipAddr.Equal(than.ipAddr)
	} else if ai.ipPrefix != nil {
		if than.ipAddr != nil {
			return ai.ipPrefix.Contains(than.ipAddr)
		} else if than.ipPrefix != nil {
			// TODO: Can something weird happen if than.IPPrefix.IP is actual shorter
			// than ai.IPPrefix but has matching leading bytes?
			return ai.ipPrefix.Contains(than.ipPrefix.IP)
		} else {
			return false
		}
	} else {
		panic("illegal state")
	}
}

func (ai *AI) UnmarshalJSON(bs []byte) error {
	var str string
	if err := json.Unmarshal(bs, &str); err != nil {
		return err
	} else if parsed, err := ParseAI(str); err != nil {
		return err
	} else {
		ai.domain = parsed.domain
		ai.ipAddr = parsed.ipAddr
		ai.ipPrefix = parsed.ipPrefix
		return nil
	}
}

func ParseAI(aiStr string) (*AI, error) {
	addr := aiStr

	if addr == "" {
		return nil, ErrIllegalAI
	}

	ai := AI{}
	if addr[0] == '[' {
		// must be IPv6
		var trimmed string
		if len(addr) > 1 {
			// avoid access of the form addr[1:0] if addr only consists of '['
			trimmed = addr[1 : len(addr)-1] // drop [...]
		} else {
			trimmed = ""
		}

		if ip := net.ParseIP(trimmed); ip != nil {
			ai.ipAddr = ip
		} else if _, net, err := net.ParseCIDR(trimmed); err == nil {
			ai.ipPrefix = net
		} else {
			return nil, ErrIllegalAddress
		}
	} else {
		// TODO: I should check labels for allowed characters of domain names
		// Only leftmost label may be wildcard
		if strings.Contains(addr[1:], "*") {
			return nil, ErrWildcard
		} else if labels := strings.Split(addr, "."); len(labels) <= 0 {
			// This should not be possible according to strings.Split docs
			panic("illegal state")
		} else if util.Contains(labels, "") {
			// No empty labels allowed
			return nil, ErrIllegalAI
		} else if strings.Contains(labels[0], "*") && len(labels[0]) > 1 {
			// If leftmost label is wildcard, leftmost label may be the wildcard only
			return nil, ErrWildcard
		} else {
			ai.domain = labels
		}
	}

	return &ai, nil
}

func (ai *AI) String() string {
	var addr string
	if ai.domain != nil {
		addr = strings.Join(ai.domain, ".")
	} else if ai.ipAddr != nil {
		addr = fmt.Sprintf("[%s]", ai.ipAddr.String())
	} else if ai.ipPrefix != nil {
		addr = fmt.Sprintf("[%s]", ai.ipPrefix.String())
	} else {
		panic("illegal state")
	}
	return addr
}

func (ai *AI) MarshalJSON() ([]byte, error) {
	return json.Marshal(ai.String())
}
