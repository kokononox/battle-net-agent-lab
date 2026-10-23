package main

import (
	"fmt"
	"os"
)

func runCLI() {
	var e error
	switch {
	case len(os.Args) == 3 && os.Args[1] == "--prepare":
		e = prepare(os.Args[2])
	case len(os.Args) == 5 && os.Args[1] == "--extract":
		e = extract(os.Args[2], os.Args[3], os.Args[4])
	case len(os.Args) == 4 && os.Args[1] == "--bundle":
		e = bundle(os.Args[2], os.Args[3])
	default:
		e = fmt.Errorf("usage: --extract DUMP WOW_EXE OUTDIR | --bundle REPORTDIR ZIP")
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
