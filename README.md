# tcamc — access-control rules to ternary-CAM entries

`tcamc` compiles the access-control lists of an industrial-park edge switch into
entries for a 2000-row ternary CAM, simulates the chip, and reports what the
compilation cost and saved.

It exists because writing port ranges directly produces far more TCAM rows than
the hardware has. A single `dst_port 8000-8999` costs six rows as plain aligned
prefixes; a realistic rule set of a few hundred range constraints overflows a
2000-row part several times over. The compiler's job is to bring that back
under capacity without changing any verdict.

## Quick start

```
go test ./...                       # unit, property and differential tests
go run ./cmd/tcamc bench            # built-in rule sets, 1M packets each
go run ./cmd/tcamc serve            # web page at http://localhost:8080
go run ./cmd/tcamc demo -out demo.html   # standalone page
go run ./cmd/tcamc compile -ruleset my.acl -html report.html
```

`bench` prints the compression table, the per-range expansion cost, online
update costs and the differential-check result. `-json` and `-html` write machine
and human readable reports.

## The rule language

```
ruleset park-edge
action 1 permit
action 2 deny
bind ge1:in ge2:in ge3:in ge4:in

rule guest-web permit
  vlan 30/0xfff          # (value & mask) == value
  dst_port 8000-8999     # inclusive range
  comment guest HTTP

rule plc permit
  src_ip 10.40.1.0/24    # IPv4 prefix
  dst_port 4840-4850
```

Fields: `src_ip`, `dst_ip` (prefix or exact), `src_port`, `dst_port`, `vlan`,
`dscp`, `est` (exact or value/mask), `src_mac`, `dst_mac`. Rules are first-match
in file order. Rules with the same `bind` set share one table.

## How each requirement is met

### 1. Port ranges become few masked entries

Ranges are coded by two composable techniques (`internal/cover`,
`internal/encode`):

* **Arbitrary ternary masks** instead of only aligned prefixes. The canonical
  prefix cover of `[lo,hi]` wastes rows; allowing any mask finds a slightly
  smaller cover. Measured against a MILP optimum on 8-bit ranges the greedy
  cover is within one row, and about 4% smaller than prefix-only.
* **Dense interval labels.** This is where the large wins are. Instead of
  indexing the table by the raw port value, the compiler cuts the port space at
  every rule's range boundaries and assigns each resulting interval a dense
  label. A range then becomes a *contiguous run of labels*, so it needs
  `log2(run length)` rows instead of `log2(field width)`.

  On the built-in rule sets this cuts the rows attributable to ranges alone from
  e.g. 2532 to 478 on the over-subscribed set, and 119 to 25 on guest-wifi.
  `bench` prints this as the `prefix > optimised` column.

The labelled fields are chosen per rule set by compiling every subset and
keeping the cheapest, so a field that does not benefit stays raw.

### 2. Rules merge only when the merge is exact

Two rules may be fused only if the fused entry matches exactly the union of the
two, and the fusion preserves the relative order of every overlapping pair
(`mergeClauses`, `mergeEntries`, `crossRuleMerge`). Merges are attempted only
within one rule, or between same-action neighbours whose intervening rows are
disjoint from both. A merge is accepted only when the union is a single cube, so
no packet's verdict can change. Labelled fields are excluded from cross-rule
merges because a label pattern's union is not the label pattern of the raw
union.

### 3. Entries are ordered by priority; non-overlapping ones move freely

The compiler treats the rule order as a partial order: any linear extension is
equally correct. `mergeEntries` relocates and fuses non-overlapping same-action
rows; the online updater uses the same freedom (see below).

### 4. Online updates move as few rows as possible

`internal/update` edits a live table with single-row writes. An insert finds the
priority window `[low, high]` implied by the new rule's overlaps, uses a free
row in it for one write and zero moves, and only shifts a run when the window is
packed. A delete clears the rule's rows, which can only remove decisions.

Two invariants make every intermediate table safe:

* Each row move is *duplicate-then-clear*: the copy is programmed before the old
  row is blanked, so no packet ever sees a gap.
* Every intermediate verdict is either the old verdict or the new one, never a
  third value. The tests in `internal/update` verify this after **every single
  write** against the reference evaluator.

The table is meant to be programmed with one free row after each entry
(`chip.NewSpaced`). That is what keeps inserts at ~1 write and 0 moved rows;
`bench` prints the same inserts on a densely packed table for comparison, where
they cost up to ~50 writes.

An online insert is only expressible on a labelled field when the new range's
boundaries are already cuts; otherwise the plan would have to relabel, which is a
full reload. `Plan.CheckInsertable` reports this rather than doing the reload
silently.

### 5. Shared tables

Rules bound to the same set of ports/directions compile to one plan, stored
once. `bench` reports both the shared table size and the sum over ports if each
had its own copy.

### 6. When it does not fit

`stats.Report` gives the shortfall in rows, the most expensive rules, and
concrete cheaper spellings: split a range at an aligned block boundary, use
arbitrary masks, or fuse two adjacent same-action rules whose ranges abut. Every
fuse suggestion is checked for equivalence by the test suite.

## Verification

The reference evaluator (`internal/ref`) walks the rules in order and matches
directly on the packet; it shares no code with the compiler beyond the rule
types. The differential tests compile every built-in rule set, program a
simulated chip, and compare the chip's action with the reference for every
packet at every attachment point. `bench -verify N` runs the same check at scale;
the default benchmark uses one million packets per rule set.

The chip model (`internal/chip`) is deliberately hardware-like: entries have
physical row indices, priority *is* the row index, and the only write primitive
modifies one row.

## Built-in rule sets

`internal/gen` generates six realistic industrial-park ACLs plus one that
overflows a 2000-row part even after optimisation. They are deterministic for a
fixed seed and heavy on unaligned port ranges.

## Layout

```
cmd/tcamc        CLI: compile, bench, serve, demo; rule parser; web page
internal/model   rule types, field widths, reference match semantics
internal/cover   exact range covers by ternary cubes (prefix, min-mask)
internal/encode  value -> dense interval label maps
internal/key     256-bit fixed-width ternary keys and field layout
internal/compile rule expansion, merging, priority layout, single-rule compile
internal/chip    software TCAM model (row-priority lookup, single-row writes)
internal/update  online insert/delete with minimal movement
internal/stats   reports, shortfall analysis, cheaper-spelling suggestions
internal/ref     reference evaluator used as ground truth
internal/gen     synthetic rule sets and packet generators
```

## Measured results

`go run ./cmd/tcamc bench -verify 1000000` (seed 1, capacity 2000 per
direction, one million packets per rule set, seven million packets total):

| rule set | rules | ranges | plain rows | optimised | ratio | range rows (prefix → optimised) | fits |
|---|---:|---:|---:|---:|---:|---:|:--|
| campus-access | 85 | 80 | 193 | 140 | 1.38× | 119 → 81 | yes |
| server-room | 37 | 36 | 82 | 49 | 1.67× | 80 → 48 | yes |
| guest-wifi | 23 | 19 | 123 | 28 | 4.39× | 119 → 25 | yes |
| industrial-iot | 41 | 51 | 276 | 68 | 4.06× | 164 → 51 | yes |
| wan-uplink | 21 | 16 | 82 | 22 | 3.73× | 77 → 17 | yes |
| shared-services | 62 | 61 | 78 | 63 | 1.24× | 77 → 62 | yes |
| over-subscribed | 1125 | 1544 | 20891 | 2900 | 7.20× | 10450 → 3319 | **short 900** |
| **total** | | | **21725** | **3270** | **6.64×** | | |

* Differential check: **7,000,000 packets, every verdict equal to the reference**.
  Each of the eight attachment points was checked on its own compiled table.
* Online updates: inserts average **1.0–1.4 row writes and 0 moved rows**
  (a spare row after each entry); the same inserts on a densely packed table
  cost up to **4322 writes / 2159 moved rows** on the over-subscribed set.
* Table sharing: the shared ACLs are stored once. `shared-services`, bound on
  eight ports, costs 63 rows shared versus 504 rows if each port had its copy.

Note on the small ratio for `campus-access` and `shared-services`: those rule
sets are dominated by per-rule prefix matches (one row each), not by port
ranges. The range-expansion column isolates requirement 1, where the ratio is
1.5× and up. `over-subscribed` is the case requirement 6 is about: 2900 rows
against 2000, short by 900, and the report lists the worst rules and cheaper
spellings.

The harness is deterministic: `bench -seed N` reproduces exactly.
