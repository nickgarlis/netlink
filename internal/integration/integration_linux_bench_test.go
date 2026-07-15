//go:build linux
// +build linux

package integration_test

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink/internal/integration/testutil"
)

func BenchmarkSendMessagesLargeNFTablesSet(b *testing.B) {
	testutil.SkipUnprivileged(b)
	sizes := []struct {
		name  string
		elems int
	}{
		{name: "1000", elems: 1000},
		{name: "10000", elems: 10000},
		{name: "100000", elems: 100000},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			ns, closeNS := testutil.NewNS(b)
			defer closeNS()
			conn := testutil.NewNftablesConn(b, ns)

			table := conn.AddTable(&nftables.Table{
				Name:   "bench",
				Family: nftables.TableFamilyIPv4,
			})
			set := &nftables.Set{
				Table:   table,
				Name:    "bench_set",
				KeyType: nftables.TypeIPAddr,
			}
			if err := conn.AddSet(set, nil); err != nil {
				b.Fatalf("AddSet: %v", err)
			}
			if err := conn.Flush(); err != nil {
				b.Fatalf("Flush: %v", err)
			}

			elems := make([]nftables.SetElement, sz.elems)
			for i := range elems {
				elems[i] = nftables.SetElement{
					Key: []byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)},
				}
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				conn.SetAddElements(set, elems)
				if err := conn.Flush(); err != nil {
					b.Fatalf("Flush: %v", err)
				}
				conn.SetDeleteElements(set, elems)
				if err := conn.Flush(); err != nil {
					b.Fatalf("Flush: %v", err)
				}
			}
		})
	}
}

func BenchmarkNftablesDump(b *testing.B) {
	testutil.SkipUnprivileged(b)
	sizes := []struct {
		name  string
		rules int
	}{
		{name: "1", rules: 1},
		{name: "8", rules: 8},
		{name: "64", rules: 64},
		{name: "512", rules: 512},
		{name: "4096", rules: 4096},
		{name: "32768", rules: 32768},
	}

	for _, sz := range sizes {
		ns, closeNS := testutil.NewNS(b)
		conn := testutil.NewNftablesConn(b, ns)

		table := &nftables.Table{
			Name:   "bench",
			Family: nftables.TableFamilyIPv4,
		}
		conn.AddTable(table)

		chain := &nftables.Chain{
			Table: table,
			Name:  "bench_chain",
			Type:  nftables.ChainTypeFilter,
		}
		conn.AddChain(chain)

		rules := make([]*nftables.Rule, sz.rules)
		for i := range sz.rules {
			rules[i] = &nftables.Rule{
				Table: table,
				Chain: chain,
				Exprs: []expr.Any{
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			}
			conn.AddRule(rules[i])
		}
		if err := conn.Flush(); err != nil {
			b.Fatalf("failed to flush nftables: %v", err)
		}

		b.Run(sz.name, func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				rules, err := conn.GetRules(table, chain)
				if err != nil {
					b.Fatalf("failed to get rules: %v", err)
				}
				if len(rules) != sz.rules {
					b.Fatalf("expected %d rules, got %d", sz.rules, len(rules))
				}
			}
		})

		closeNS()
	}
}
