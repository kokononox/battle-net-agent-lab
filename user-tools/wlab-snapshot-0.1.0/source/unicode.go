package main

import "unicode/utf16"

func utf16Decode(v []uint16) []rune { return utf16.Decode(v) }
