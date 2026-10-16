package main

import (
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
	"testing"
)

func TestRemainderActions(t *testing.T) {
	closed := zkapi.AddressWithdrawalStatus{Phase: "complete", Address: "0x1111111111111111111111111111111111111111", Destination: withdrawalTestDestination, ChainID: 1}
	for _, test := range []struct{ phase, balance, destination, want string }{
		{"ready", "0", "", "empty"}, {"ready", "100", "", "quote"},
		{"quoted", "100", withdrawalTestDestination, "quote"},
		{"return_pending", "100", withdrawalTestDestination, "resume"},
		{"complete", "100", withdrawalTestDestination, "done"},
		{"return_pending", "100", closed.Address, ""},
		{"reverted", "100", withdrawalTestDestination, ""},
	} {
		state := zkapi.AddressReturnStatus{Phase: test.phase, ETHBalance: test.balance, Address: closed.Address, ChainID: 1, Destination: test.destination}
		got, err := remainderAction(closed, state)
		if got != test.want || (err != nil) != (test.want == "") {
			t.Fatal(test, got, err)
		}
	}
	closed.Phase = "confirming"
	if _, err := remainderAction(closed, zkapi.AddressReturnStatus{}); err == nil {
		t.Fatal("sweeps before private completion")
	}
}
