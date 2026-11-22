// Package gen generates synthetic but realistic industrial-park access-control
// rule sets. They are deliberately heavy on port ranges: that is what makes
// TCAM tables overflow in the field, and it is what the compiler is for.
//
// Every rule set is deterministic for a fixed seed, so benchmark numbers are
// reproducible.
package gen

import (
	"fmt"
	"math/rand"
	"sort"

	"tcamc/internal/model"
)

// Profile selects one of the named rule-set shapes.
type Profile struct {
	Name  string
	Build func(rng *rand.Rand) *model.RuleSet
}

// Profiles lists every built-in rule set.
var Profiles = []Profile{
	{"campus-access", campusAccess},
	{"server-room", serverRoom},
	{"guest-wifi", guestWifi},
	{"industrial-iot", industrialIoT},
	{"wan-uplink", wanUplink},
	{"shared-services", sharedServices},
	{"over-subscribed", overSubscribed},
}

// All builds every profile with the given seed.
func All(seed int64) []*model.RuleSet {
	out := make([]*model.RuleSet, 0, len(Profiles))
	for i, p := range Profiles {
		out = append(out, p.Build(rand.New(rand.NewSource(seed+int64(i)*7919))))
	}
	return out
}

// Actions used across rule sets. Rule ids are never 0 so a table miss (default
// permit, id 0) is distinguishable from a matched permit rule.
var (
	Permit = model.Action{ID: 1, Name: "permit", Permit: true}
	Deny   = model.Action{ID: 2, Name: "deny", Permit: false}
	Log    = model.Action{ID: 3, Name: "permit+log", Permit: true}
)

type builder struct {
	rng   *rand.Rand
	rules []*model.Rule
	n     int
}

func newBuilder(rng *rand.Rand) *builder { return &builder{rng: rng} }

func (b *builder) add(bindings []string, action model.Action, comment string, ms ...model.Match) {
	b.n++
	b.rules = append(b.rules, &model.Rule{
		ID:       fmt.Sprintf("r%03d", b.n),
		Bindings: bindings,
		Matches:  ms,
		Action:   action,
		Comment:  comment,
	})
}

func prefix(field string, addr uint32, plen uint8) model.Match {
	m := model.Match{Field: field, Kind: model.KindPrefix, Value: uint64(addr), Plen: plen}
	return m
}

func rangeM(field string, lo, hi uint64) model.Match {
	return model.Match{Field: field, Kind: model.KindRange, Lo: lo, Hi: hi}
}

func exact(field string, v uint64) model.Match {
	return model.Match{Field: field, Kind: model.KindExact, Value: v}
}

func mask(field string, v, m uint64) model.Match {
	return model.Match{Field: field, Kind: model.KindMask, Value: v, Mask: m}
}

func ip(a, b, c, d uint32) uint32 {
	return a<<24 | b<<16 | c<<8 | d
}

var bindingsAll = []string{
	"ge1:in", "ge2:in", "ge3:in", "ge4:in",
	"ge1:out", "ge2:out", "ge3:out", "ge4:out",
}

func dirsIn() []string {
	return []string{"ge1:in", "ge2:in", "ge3:in", "ge4:in"}
}

// servicePorts is a realistic catalogue of service port ranges. Many of them
// are deliberately unaligned, which is what makes prefix expansion expensive.
var servicePorts = [][2]uint64{
	{20, 21}, {22, 22}, {23, 23}, {25, 25}, {49, 49}, {53, 53}, {67, 68},
	{69, 69}, {80, 80}, {88, 88}, {110, 110}, {111, 111}, {119, 119},
	{123, 123}, {135, 139}, {143, 143}, {161, 162}, {179, 179}, {389, 389},
	{443, 443}, {445, 445}, {464, 464}, {500, 500}, {502, 502}, {514, 514},
	{515, 515}, {520, 520}, {546, 547}, {554, 554}, {587, 587}, {631, 631},
	{636, 636}, {646, 646}, {873, 873}, {990, 995}, {1025, 1030},
	{1080, 1080}, {1194, 1194}, {1234, 1235}, {1433, 1434}, {1521, 1521},
	{1701, 1701}, {1723, 1723}, {1812, 1813}, {1883, 1883}, {1900, 1905},
	{2000, 2003}, {2049, 2049}, {2222, 2222}, {2375, 2376}, {2404, 2405},
	{3000, 3001}, {3128, 3128}, {3260, 3260}, {3306, 3306}, {3389, 3400},
	{3478, 3479}, {3544, 3544}, {3702, 3702}, {3784, 3786}, {4000, 4001},
	{4500, 4500}, {47808, 47809}, {4840, 4840}, {4843, 4843}, {5000, 5001},
	{5060, 5061}, {5190, 5190}, {5222, 5223}, {5353, 5353}, {5432, 5433},
	{5555, 5556}, {5672, 5673}, {5900, 5901}, {5985, 5986}, {6000, 6002},
	{6379, 6379}, {6443, 6443}, {7000, 7003}, {8000, 8010}, {8080, 8090},
	{8443, 8450}, {8888, 8889}, {9000, 9100}, {9090, 9091}, {9200, 9205},
	{9443, 9444}, {9999, 10000}, {11211, 11211}, {12000, 12001},
	{13720, 13721}, {16162, 16162}, {16384, 16390}, {20000, 20010},
	{25565, 25566}, {27017, 27018}, {32768, 32770}, {33060, 33061},
	{44818, 44819}, {49152, 49160}, {50000, 50010}, {54321, 54322},
	{55555, 55560}, {60000, 60005}, {64738, 64739},
}

func (b *builder) service(i int) [2]uint64 {
	return servicePorts[i%len(servicePorts)]
}

// campusAccess: VLAN segmentation for office/guest/workshop traffic with a
// broad service-port catalogue.
func campusAccess(rng *rand.Rand) *model.RuleSet {
	b := newBuilder(rng)
	bs := bindingsAll
	// Management access: SSH/RDP only from the admin subnet.
	b.add(bs, Permit, "admin management",
		prefix("src_ip", ip(10, 20, 0, 0), 16),
		rangeM("dst_port", 22, 22), mask("proto", 6, 0xff))
	b.add(bs, Permit, "admin RDP range",
		prefix("src_ip", ip(10, 20, 0, 0), 16),
		rangeM("dst_port", 3389, 3400), mask("proto", 6, 0xff))
	// Guest VLAN: internet only, no internal ranges.
	b.add(bs, Deny, "guest to server farm",
		mask("vlan", 30, 0xfff),
		prefix("dst_ip", ip(10, 30, 0, 0), 16))
	b.add(bs, Deny, "guest to workshop",
		mask("vlan", 30, 0xfff),
		prefix("dst_ip", ip(10, 40, 0, 0), 16))
	b.add(bs, Permit, "guest web",
		mask("vlan", 30, 0xfff),
		rangeM("dst_port", 80, 80))
	b.add(bs, Permit, "guest https",
		mask("vlan", 30, 0xfff),
		rangeM("dst_port", 443, 443))
	b.add(bs, Permit, "guest dns/dhcp",
		mask("vlan", 30, 0xfff),
		rangeM("dst_port", 53, 68))
	b.add(bs, Deny, "guest catch-all",
		mask("vlan", 30, 0xfff))
	// Workshop PLC/SCADA ports: a long tail of small ranges.
	for i := 0; i < 22; i++ {
		p := b.service(i + 20)
		b.add(dirsIn(), Permit, fmt.Sprintf("workshop plc %d", i),
			prefix("src_ip", ip(10, 40, uint32(i%8), 0), 21),
			rangeM("dst_port", p[0], p[1]))
	}
	// Server subnet: allow the service catalogue to the app servers.
	for i := 0; i < 40; i++ {
		p := b.service(i)
		act := Permit
		if i%7 == 3 {
			act = Log
		}
		b.add(bs, act, fmt.Sprintf("server svc %d", i),
			prefix("dst_ip", ip(10, 30, uint32(i%16), 0), 20),
			rangeM("dst_port", p[0], p[1]),
			mask("proto", 6, 0xff))
	}
	// Oracle/Postgres/MySQL admin ranges.
	b.add(bs, Permit, "db admin",
		prefix("src_ip", ip(10, 20, 5, 0), 24),
		prefix("dst_ip", ip(10, 30, 9, 0), 24),
		rangeM("dst_port", 1433, 1434))
	b.add(bs, Permit, "db admin pg",
		prefix("src_ip", ip(10, 20, 5, 0), 24),
		prefix("dst_ip", ip(10, 30, 9, 0), 24),
		rangeM("dst_port", 5432, 5433))
	b.add(bs, Deny, "block telnet to servers",
		prefix("dst_ip", ip(10, 30, 0, 0), 16),
		rangeM("dst_port", 23, 23))
	b.add(bs, Permit, "established return",
		exact("est", 1))
	// Per-department web egress with awkward port bands.
	bands := [][2]uint64{{7000, 7009}, {8000, 8010}, {8080, 8090}, {8443, 8450},
		{9000, 9100}, {9200, 9205}, {10000, 10010}, {11211, 11211},
		{12000, 12001}, {20000, 20010}}
	for i, bd := range bands {
		b.add(dirsIn(), Permit, fmt.Sprintf("dept egress %d", i),
			prefix("src_ip", ip(10, 20, uint32(10+i), 0), 24),
			rangeM("dst_port", bd[0], bd[1]))
	}
	b.add(bs, Deny, "default deny workshop",
		prefix("src_ip", ip(10, 40, 0, 0), 16))
	return &model.RuleSet{Name: "campus-access", Rules: b.rules}
}

// serverRoom is prefix-heavy: many /24 pairs and service ranges.
func serverRoom(rng *rand.Rand) *model.RuleSet {
	b := newBuilder(rng)
	bs := bindingsAll
	// Paired /24 peer rules: adjacent rules with identical action and
	// almost-identical prefixes, which the merger can sometimes fuse.
	for i := 0; i < 20; i++ {
		act := Permit
		if i%5 == 4 {
			act = Deny
		}
		p := b.service(i * 3)
		b.add(bs, act, fmt.Sprintf("peer %d", i),
			prefix("src_ip", ip(10, 30, uint32(i), 0), 24),
			prefix("dst_ip", ip(10, 30, uint32((i+1)%20), 0), 24),
			rangeM("dst_port", p[0], p[1]))
	}
	// Wide port ranges.
	wides := [][2]uint64{{1024, 2047}, {2048, 4095}, {4096, 8191}, {8192, 16383},
		{16384, 32767}, {32768, 49151}, {49152, 65535}, {8000, 9000},
		{10000, 20000}, {30000, 40000}, {50000, 65000}}
	for i, w := range wides {
		act := Permit
		if i%3 == 2 {
			act = Deny
		}
		b.add(bs, act, fmt.Sprintf("wide %d", i),
			prefix("dst_ip", ip(10, 31, uint32(i), 0), 24),
			rangeM("dst_port", w[0], w[1]))
	}
	// NTP/DNS infrastructure.
	b.add(bs, Permit, "infra dns",
		prefix("dst_ip", ip(10, 30, 0, 53), 32),
		rangeM("dst_port", 53, 53))
	b.add(bs, Permit, "infra ntp",
		prefix("dst_ip", ip(10, 30, 0, 123), 32),
		rangeM("dst_port", 123, 123))
	b.add(bs, Permit, "infra syslog range",
		prefix("dst_ip", ip(10, 30, 0, 0), 24),
		rangeM("dst_port", 514, 515))
	b.add(bs, Deny, "block smb out",
		rangeM("dst_port", 137, 139),
		rangeM("src_port", 137, 139))
	b.add(bs, Permit, "established",
		exact("est", 1))
	b.add(bs, Deny, "default deny server room",
		prefix("dst_ip", ip(10, 31, 0, 0), 16))
	return &model.RuleSet{Name: "server-room", Rules: b.rules}
}

// guestWifi uses broad, awkward ranges.
func guestWifi(rng *rand.Rand) *model.RuleSet {
	b := newBuilder(rng)
	bs := bindingsAll
	b.add(bs, Deny, "guest to mgmt",
		mask("vlan", 30, 0xfff),
		prefix("dst_ip", ip(10, 20, 0, 0), 16))
	b.add(bs, Deny, "guest to iot",
		mask("vlan", 30, 0xfff),
		prefix("dst_ip", ip(10, 40, 0, 0), 16))
	b.add(bs, Permit, "guest ephemeral",
		mask("vlan", 30, 0xfff),
		rangeM("src_port", 49152, 65535),
		exact("est", 1))
	b.add(bs, Permit, "guest web range",
		mask("vlan", 30, 0xfff),
		rangeM("dst_port", 8000, 8999))
	b.add(bs, Permit, "guest https range",
		mask("vlan", 30, 0xfff),
		rangeM("dst_port", 8443, 9443))
	rngRanges := [][2]uint64{
		{1024, 65535}, {1, 1023}, {67, 69}, {1000, 2000}, {3000, 3100},
		{4000, 4100}, {5000, 5100}, {6000, 6100}, {7000, 7100},
		{12000, 13000}, {20000, 20100}, {25000, 26000}, {32768, 33768},
		{40000, 41000}, {50000, 51000}, {60000, 61000},
	}
	for i, r := range rngRanges {
		b.add(bs, Permit, fmt.Sprintf("guest allowed %d", i),
			mask("vlan", 30, 0xfff),
			rangeM("dst_port", r[0], r[1]))
	}
	b.add(bs, Deny, "guest default",
		mask("vlan", 30, 0xfff))
	b.add(bs, Permit, "staff any",
		mask("vlan", 10, 0xfff))
	return &model.RuleSet{Name: "guest-wifi", Rules: b.rules}
}

// industrialIoT: many tiny unaligned PLC ranges, plus both direction ports.
func industrialIoT(rng *rand.Rand) *model.RuleSet {
	b := newBuilder(rng)
	bs := bindingsAll
	// Per-line PLC rules: 24 lines, each with an unaligned port block.
	for i := 0; i < 24; i++ {
		lo := uint64(15000 + i*37)
		hi := lo + uint64(20+i%13)
		act := Permit
		if i%9 == 8 {
			act = Deny
		}
		b.add(bs, act, fmt.Sprintf("line %d plc", i),
			prefix("src_ip", ip(10, 40, uint32(i), 0), 24),
			prefix("dst_ip", ip(10, 41, uint32(i), 0), 24),
			rangeM("dst_port", lo, hi))
	}
	// SCADA masters to PLCs with a narrow source range.
	for i := 0; i < 12; i++ {
		base := uint64(40000 + i*17)
		b.add(dirsIn(), Permit, fmt.Sprintf("scada %d", i),
			prefix("src_ip", ip(10, 42, uint32(i%4), 0), 22),
			rangeM("src_port", base, base+uint64(5+i%4)),
			rangeM("dst_port", 4840, 4840))
	}
	// Building management, BACnet.
	b.add(bs, Permit, "bacnet",
		prefix("dst_ip", ip(10, 41, 0, 0), 16),
		rangeM("dst_port", 47808, 47809))
	b.add(bs, Permit, "modbus",
		prefix("dst_ip", ip(10, 41, 0, 0), 16),
		rangeM("dst_port", 502, 503))
	b.add(bs, Deny, "ics to office",
		prefix("src_ip", ip(10, 41, 0, 0), 16),
		prefix("dst_ip", ip(10, 20, 0, 0), 16))
	b.add(bs, Deny, "ics to internet",
		prefix("src_ip", ip(10, 41, 0, 0), 16),
		prefix("dst_ip", 0, 0))
	b.add(bs, Permit, "iot ntp",
		prefix("dst_ip", ip(10, 41, 0, 1), 32),
		rangeM("dst_port", 123, 124))
	return &model.RuleSet{Name: "industrial-iot", Rules: b.rules}
}

// wanUplink: big ranges and many prefixes, the worst case for expansion.
func wanUplink(rng *rand.Rand) *model.RuleSet {
	b := newBuilder(rng)
	bs := bindingsAll
	b.add(bs, Deny, "bogons",
		prefix("dst_ip", ip(0, 0, 0, 0), 8))
	b.add(bs, Deny, "bogon 10/8 from wan",
		prefix("src_ip", ip(10, 0, 0, 0), 8))
	b.add(bs, Deny, "bogon 172.16",
		prefix("src_ip", ip(172, 16, 0, 0), 12))
	b.add(bs, Deny, "bogon 192.168",
		prefix("src_ip", ip(192, 168, 0, 0), 16))
	// Public service exposure with wide, awkward ranges.
	exposures := [][3]uint64{
		{80, 80, 0}, {443, 443, 0}, {8000, 8100, 0}, {8443, 8500, 0},
		{9000, 9500, 0}, {10000, 11000, 0}, {20000, 21000, 0},
		{30000, 31000, 0}, {40000, 41000, 0}, {50000, 50100, 0},
		{60000, 60500, 0},
	}
	for i, e := range exposures {
		b.add(bs, Permit, fmt.Sprintf("expose %d", i),
			prefix("dst_ip", ip(203, 0, 113, uint32(10+i)), 32),
			rangeM("dst_port", e[0], e[1]),
			mask("proto", 6, 0xff))
	}
	// Return traffic.
	b.add(bs, Permit, "established return",
		exact("est", 1),
		rangeM("src_port", 1024, 65535))
	// VoIP.
	b.add(bs, Permit, "sip",
		prefix("dst_ip", ip(203, 0, 113, 50), 32),
		rangeM("dst_port", 5060, 5061))
	b.add(bs, Permit, "rtp",
		prefix("dst_ip", ip(203, 0, 113, 50), 32),
		rangeM("dst_port", 16384, 32767))
	b.add(bs, Permit, "vpn",
		prefix("dst_ip", ip(203, 0, 113, 60), 32),
		rangeM("dst_port", 500, 500))
	b.add(bs, Permit, "vpn nat-t",
		prefix("dst_ip", ip(203, 0, 113, 60), 32),
		rangeM("dst_port", 4500, 4501))
	b.add(bs, Deny, "wan default",
		prefix("dst_ip", 0, 0))
	return &model.RuleSet{Name: "wan-uplink", Rules: b.rules}
}

// sharedServices: one rule set bound to eight attachment points. This is the
// sharing case: the compiled table is stored once and looked up from every
// port, and the benchmark reports the entries that a per-port copy would need.
func sharedServices(rng *rand.Rand) *model.RuleSet {
	b := newBuilder(rng)
	bs := bindingsAll
	for i := 0; i < 60; i++ {
		p := b.service(i * 2)
		act := Permit
		if i%6 == 2 {
			act = Log
		}
		b.add(bs, act, fmt.Sprintf("shared svc %d", i),
			prefix("src_ip", ip(10, 50, uint32(i%16), 0), 24),
			prefix("dst_ip", ip(10, 60, uint32(i%8), 0), 24),
			rangeM("dst_port", p[0], p[1]))
	}
	b.add(bs, Deny, "shared deny admin",
		prefix("dst_ip", ip(10, 60, 0, 0), 16),
		rangeM("dst_port", 22, 23))
	b.add(bs, Permit, "shared established", exact("est", 1))
	return &model.RuleSet{Name: "shared-services", Rules: b.rules}
}

// Packets generates test packets for a rule set: random keys plus keys that
// land on the interesting values (range endpoints, exact values, prefix edges,
// and one-past values) so a differential test actually exercises the covers.
func Packets(rs *model.RuleSet, n int, seed int64) []model.Key {
	rng := rand.New(rand.NewSource(seed))
	// Gather interesting values per field.
	inter := map[string][]uint64{}
	add := func(f string, v uint64) { inter[f] = append(inter[f], v) }
	for _, r := range rs.Rules {
		for _, m := range r.Matches {
			switch m.Kind {
			case model.KindRange:
				add(m.Field, m.Lo)
				add(m.Field, m.Hi)
				if m.Lo > 0 {
					add(m.Field, m.Lo-1)
				}
				if m.Hi+1 <= model.Meta[m.Field].Max() {
					add(m.Field, m.Hi+1)
				}
				add(m.Field, (m.Lo+m.Hi)/2)
			case model.KindExact:
				add(m.Field, m.Value)
				if m.Value > 0 {
					add(m.Field, m.Value-1)
				}
				add(m.Field, m.Value+1)
			case model.KindPrefix:
				mask := ^uint64(0)
				if m.Plen < 32 {
					mask = (uint64(1)<<uint(m.Plen) - 1) << (32 - uint(m.Plen))
				}
				add(m.Field, m.Value&mask)
				add(m.Field, m.Value|(^mask&0xffffffff))
				if m.Plen < 32 {
					add(m.Field, (m.Value&mask)|(uint64(1)<<(32-uint(m.Plen)-1))-1)
					add(m.Field, (m.Value&mask)|(uint64(1)<<(32-uint(m.Plen)-1)))
				}
			case model.KindMask:
				add(m.Field, m.Value)
			}
		}
	}
	out := make([]model.Key, 0, n)
	for i := 0; i < n; i++ {
		k := model.Key{}
		for _, f := range model.Fields {
			width := model.Meta[f].Width
			var v uint64
			if vals := inter[f]; len(vals) > 0 && rng.Intn(2) == 0 {
				v = vals[rng.Intn(len(vals))]
				if rng.Intn(8) == 0 {
					// Occasionally perturb an interesting value.
					d := uint64(rng.Intn(5)) - 2
					if d&(1<<63) != 0 {
						if v < -d {
							d = 0
						}
					}
					v += d
				}
			} else {
				switch width {
				case 32:
					// Bias toward the prefixes in use.
					v = uint64(rng.Intn(1<<24)) | uint64(rng.Intn(2))<<24 |
						uint64(10)<<24
					if rng.Intn(4) == 0 {
						v = uint64(rng.Uint32())
					}
				case 16:
					v = uint64(rng.Intn(65536))
					if rng.Intn(2) == 0 {
						v = uint64(rng.Intn(1024)) | uint64(rng.Intn(2))<<15
					}
				case 12:
					v = uint64(rng.Intn(64))
					if rng.Intn(2) == 0 {
						v = uint64(rng.Intn(4096))
					}
				case 8:
					v = uint64(rng.Intn(256))
				case 6:
					v = uint64(rng.Intn(64))
				case 1:
					v = uint64(rng.Intn(2))
				default:
					v = rng.Uint64() & (uint64(1)<<width - 1)
				}
			}
			v &= uint64(1)<<width - 1
			k[f] = v
		}
		out = append(out, k)
	}
	return out
}

// Summary renders a compact description of a rule set, used by the CLI.
func Summary(rs *model.RuleSet) string {
	ranges := 0
	for _, r := range rs.Rules {
		for _, m := range r.Matches {
			if m.Kind == model.KindRange {
				ranges++
			}
		}
	}
	ports := map[string]bool{}
	for _, r := range rs.Rules {
		for _, b := range r.Bindings {
			ports[b] = true
		}
	}
	order := make([]string, 0, len(ports))
	for p := range ports {
		order = append(order, p)
	}
	sort.Strings(order)
	return fmt.Sprintf("%s: %d rules, %d range constraints, %d attachment points",
		rs.Name, len(rs.Rules), ranges, len(order))
}

// overSubscribed is a rule set that genuinely overflows a 2000-entry part even
// after optimisation: it is what the "tell me how much is missing" report is
// for. It combines many wide unaligned ranges with per-host prefix rules, so
// the plain expansion is several thousand entries.
func overSubscribed(rng *rand.Rand) *model.RuleSet {
	b := newBuilder(rng)
	bs := bindingsAll
	// 180 host rules, each with an unaligned 100-300 port range.
	for i := 0; i < 700; i++ {
		lo := uint64(1024 + i*311)
		if lo > 65000 {
			lo = 1024 + uint64(i*311)%64000
		}
		hi := lo + uint64(101+i%197)
		if hi > 65535 {
			hi = 65535
		}
		act := Permit
		if i%11 == 10 {
			act = Deny
		}
		b.add(bs, act, fmt.Sprintf("host %d range", i),
			prefix("dst_ip", ip(10, 50+uint32(i/256), uint32(i%256), 0), 28),
			rangeM("dst_port", lo, hi))
	}
	// 90 source/destination pairs with two ranges each.
	for i := 0; i < 420; i++ {
		slo := uint64(1000 + i*137)
		if slo > 60000 {
			slo = 1000 + uint64(i*137)%60000
		}
		dlo := uint64(20000 + i*211)
		if dlo > 60000 {
			dlo = 20000 + uint64(i*211)%45000
		}
		act := Log
		if i%7 == 6 {
			act = Deny
		}
		b.add(bs, act, fmt.Sprintf("pair %d", i),
			prefix("src_ip", ip(10, 60, uint32(i%32), 0), 24),
			rangeM("src_port", slo, slo+uint64(37+i%41)),
			rangeM("dst_port", dlo, dlo+uint64(51+i%73)))
	}
	// A handful of wide ranges.
	wide := [][2]uint64{{1, 65534}, {1000, 65000}, {2000, 60000}, {3000, 50000}}
	for i, w := range wide {
		b.add(bs, Permit, fmt.Sprintf("wide %d", i),
			prefix("dst_ip", ip(10, 70, uint32(i), 0), 24),
			rangeM("dst_port", w[0], w[1]))
	}
	b.add(bs, Deny, "catch-all", prefix("dst_ip", 0, 0))
	return &model.RuleSet{Name: "over-subscribed", Rules: b.rules}
}
