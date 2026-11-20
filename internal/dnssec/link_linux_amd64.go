package dnssec

// The prebuilt Rust static library is linked through cgo rather than as a
// *.syso: Go 1.27.3+ rejects `ar` archives named .syso. See build.sh for how
// the library is built (no LTO / bitcode sections, which cgo also rejects).

// #cgo LDFLAGS: ${SRCDIR}/libdnssec_linux_amd64.a -lm -ldl -lpthread
import "C"
