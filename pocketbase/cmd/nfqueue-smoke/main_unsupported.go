//go:build !linux

package main

import "fmt"

func main() { fmt.Println("nfqueue-smoke is only available on Linux") }
