package cloudflare

import (
	"fmt"
	"math/bits"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"unicode"
)

type Targets struct {
	IPs       []netip.Addr
	Subnets   []netip.Prefix
	Canonical string
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/3"), netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::ffff:0:0/96"), netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

func publicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsGlobalUnicast() && ip.Zone() == "" &&
		!slices.ContainsFunc(nonPublic, func(block netip.Prefix) bool { return block.Contains(ip) })
}

// ParseTargets accepts a list of explicit public addresses and CIDRs. Network
// ranges are sampled; they are never expanded into a list of every address.
func ParseTargets(input string) (Targets, error) {
	if len(input) > 16384 {
		return Targets{}, fmt.Errorf("list is longer than 16 KiB")
	}
	tokens := strings.FieldsFunc(input, func(r rune) bool {
		return unicode.IsSpace(r) || r == ',' || r == ';' || r == '،'
	})
	if len(tokens) > 256 {
		return Targets{}, fmt.Errorf("list contains more than 256 entries")
	}
	var result Targets
	var canonical []string
	seen := make(map[string]bool)
	for i, token := range tokens {
		var key string
		if ip, err := netip.ParseAddr(token); err == nil && publicAddress(ip) {
			ip = ip.Unmap()
			key = ip.String()
			if !seen[key] {
				result.IPs = append(result.IPs, ip)
			}
		} else if prefix, err := netip.ParsePrefix(token); err == nil &&
			!prefix.Addr().Is4In6() && publicAddress(prefix.Masked().Addr()) &&
			!slices.ContainsFunc(nonPublic, func(block netip.Prefix) bool { return block.Overlaps(prefix) }) {
			prefix = prefix.Masked()
			if prefix.Bits() == prefix.Addr().BitLen() {
				ip := prefix.Addr()
				key = ip.String()
				if !seen[key] {
					result.IPs = append(result.IPs, ip)
				}
			} else {
				key = prefix.String()
				if !seen[key] {
					result.Subnets = append(result.Subnets, prefix)
				}
			}
		} else {
			return Targets{}, fmt.Errorf("entry %d must be a public IP or CIDR", i+1)
		}
		if !seen[key] {
			canonical = append(canonical, key)
			seen[key] = true
		}
	}
	result.Canonical = strings.Join(canonical, "\n")
	return result, nil
}

func (t Targets) allows(ip netip.Addr) bool {
	ip = ip.Unmap()
	return publicAddress(ip) && (isCloudflare(ip) || slices.Contains(t.IPs, ip) ||
		slices.ContainsFunc(t.Subnets, func(prefix netip.Prefix) bool { return prefix.Contains(ip) }))
}

func (t Targets) ranges() []netip.Prefix {
	result := make([]netip.Prefix, 0, len(prefixes)+len(t.Subnets))
	for _, entry := range prefixes {
		result = append(result, netip.MustParsePrefix(entry))
	}
	for _, prefix := range t.Subnets {
		if !slices.Contains(result, prefix) {
			result = append(result, prefix)
		}
	}
	return result
}

// Each sample is drawn from a different partition of the prefix. Small
// prefixes can be covered completely, and even /32 or /128 are safe to use.
func spreadSamples(prefix netip.Prefix, count int) []netip.Addr {
	if count < 1 {
		return nil
	}
	width := min(bits.Len(uint(count-1)), prefix.Addr().BitLen()-prefix.Bits())
	partitions := rand.Perm(1 << width)
	base := prefix.Masked().Addr().AsSlice()
	result := make([]netip.Addr, 0, min(count, len(partitions)))
	for _, slot := range partitions[:min(count, len(partitions))] {
		address := slices.Clone(base)
		for i := range width {
			bit := prefix.Bits() + i
			if slot&(1<<(width-i-1)) != 0 {
				address[bit/8] |= byte(128 >> (bit % 8))
			}
		}
		branch, _ := netip.AddrFromSlice(address)
		result = append(result, sample(netip.PrefixFrom(branch, prefix.Bits()+width)))
	}
	return result
}
