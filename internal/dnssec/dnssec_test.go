package dnssec

import (
	"net"
	"strings"
	"testing"
)

func sendQuery(pb *ProofBuilder, server string) error {
	for {
		query := pb.GetNextQuery()
		if query == nil {
			return nil
		}
		conn, err := net.Dial("tcp", server)
		if err != nil {
			return err
		}
		msgLen := len(*query)
		buf := make([]byte, 2+msgLen)
		buf[0] = byte(msgLen >> 8)
		buf[1] = byte(msgLen)
		copy(buf[2:], *query)
		_, _ = conn.Write(buf)
		lenBuf := make([]byte, 2)
		_, _ = conn.Read(lenBuf)
		respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		resp := make([]byte, respLen)
		_, _ = conn.Read(resp)
		_ = conn.Close()
		_ = pb.ProcessQueryResponse(resp)
	}
}

func TestVerifyMattCorallo(t *testing.T) {
	name := "matt.user._bitcoin-payment.mattcorallo.com."
	builder := InitProofBuilder(name, 16)
	if builder == nil || *builder == nil {
		t.Fatal("failed to init proof builder")
	}
	if err := sendQuery(*builder, "8.8.8.8:53"); err != nil {
		t.Fatal(err)
	}
	proof := (*builder).GetUnverifiedProof()
	if proof == nil {
		t.Fatal("no proof generated")
	}
	result := VerifyByteStream(*proof, name)
	if !strings.Contains(result, "bitcoin:") {
		t.Fatalf("expected bitcoin: URI in result, got: %s", result)
	}
	t.Logf("OK: %s", result[:80])
}

func TestNXDOMAIN(t *testing.T) {
	name := "doesnotexist.user._bitcoin-payment.mattcorallo.com."
	builder := InitProofBuilder(name, 16)
	if builder == nil || *builder == nil {
		t.Fatal("failed to init proof builder")
	}
	if err := sendQuery(*builder, "8.8.8.8:53"); err != nil {
		t.Fatal(err)
	}
	proof := (*builder).GetUnverifiedProof()
	if proof != nil {
		t.Fatal("expected no proof for NXDOMAIN")
	}
	t.Log("OK: no proof for nonexistent name")
}

func TestSimpleDnssecNinja(t *testing.T) {
	name := "simple.user._bitcoin-payment.dnssec_proof_tests.bitcoin.ninja."
	builder := InitProofBuilder(name, 16)
	if builder == nil || *builder == nil {
		t.Fatal("failed to init proof builder")
	}
	if err := sendQuery(*builder, "8.8.8.8:53"); err != nil {
		t.Fatal(err)
	}
	proof := (*builder).GetUnverifiedProof()
	if proof == nil {
		t.Fatal("no proof generated")
	}
	result := VerifyByteStream(*proof, name)
	if !strings.Contains(result, "bitcoin:") {
		t.Fatalf("expected bitcoin: URI in result, got: %s", result)
	}
	t.Logf("OK: %s", result[:80])
}
