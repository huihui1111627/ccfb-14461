// Command tcamc compiles ACL rule sets into ternary-CAM tables, simulates the
// chip, and reports compression and online-update costs.
//
//	tcamc compile   -ruleset FILE [-capacity 2000] [-json OUT] [-html OUT]
//	tcamc bench     [-verify 1000000] [-json OUT] [-html OUT]
//	tcamc serve     [-addr :8080]
//	tcamc demo      [-out demo.html]
//
// The rule set file format is a small indented text format, documented in
// README.md; gen.Profiles also builds the built-in benchmark sets.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "compile":
		err = runCompile(args)
	case "bench":
		err = runBench(args)
	case "serve":
		err = runServe(args)
	case "demo":
		err = runDemo(args)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `tcamc -- access-control rule compiler for a small ternary CAM

usage:
  tcamc compile -ruleset FILE [-capacity N] [-json OUT] [-html OUT]
  tcamc bench   [-verify N] [-capacity N] [-json OUT] [-html OUT]
  tcamc serve   [-addr :8080]
  tcamc demo    [-out FILE]

The compiler expands port ranges into masked entries, merges equivalent
entries, shares tables across ports, reports shortfall when the rule set does
not fit, and simulates online inserts and deletes row by row.
`)
}

func mustFlag(fs *flag.FlagSet) {
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage of %s:\n", fs.Name())
		fs.PrintDefaults()
	}
}
