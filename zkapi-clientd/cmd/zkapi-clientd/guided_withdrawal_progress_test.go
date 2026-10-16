package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

func TestGuidedWithdrawalRefreshesFeePaymentInPlace(t *testing.T) {
	f := &withdrawalWizardFixture{}
	u := &recordingSetupDisplay{fundingWizardUI: fundingWizardUI{answers: []string{withdrawalTestDestination}}}
	f.quote = func(call int, _ string, _ uint64, _ string) (zkapi.AddressPaymentQuote, error) {
		quote := withdrawalWizardQuote()
		switch call {
		case 1:
			withdrawalQuoteFunds(&quote, 0, 25000, 30000)
		case 2:
			withdrawalQuoteFunds(&quote, 0, 29000, 34000)
		default:
			withdrawalQuoteFunds(&quote, 0, 31000, 36000)
		}
		return quote, nil
	}
	waits := 0
	err := guidedWithdrawal(context.Background(), f, u, func(context.Context) error {
		waits++
		if u.active != "" || !strings.Contains(u.payments[len(u.payments)-1], "Send at least:") {
			t.Fatal("fee wait must show payment instructions without redundant status")
		}
		if waits == 3 {
			return context.Canceled
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || u.active != "" || f.approveCalls != 0 || u.continues != 0 {
		t.Fatal("cancelling the fee wait did not stop cleanly")
	}
	if len(u.payments) != 2 || strings.Contains(u.String(), "Scan with") || strings.Contains(u.String(), "Waiting for ETH:") {
		t.Fatal("fee polling appended cards or live status to the permanent transcript")
	}
}

func TestGuidedWithdrawalRestoresStageAfterInterruptedRecovery(t *testing.T) {
	f := &withdrawalWizardFixture{}
	u := &recordingSetupDisplay{}
	initial := withdrawalWizardState("withdrawal_pending")
	f.resume = func(call int, _ string, _ uint64) (zkapi.AddressWithdrawalStatus, error) {
		if call == 1 {
			return zkapi.AddressWithdrawalStatus{}, errors.New("temporary response failure")
		}
		return withdrawalWizardState("complete"), nil
	}
	f.status = func(call int) (zkapi.AddressWithdrawalStatus, error) {
		if call == 1 {
			return zkapi.AddressWithdrawalStatus{}, errors.New("temporarily unavailable")
		}
		return initial, nil
	}
	if err := finishGuidedWithdrawal(context.Background(), f, initial, u, immediateWizardPoll); err != nil {
		t.Fatal(err)
	}
	updates := strings.Join(u.progress, "\n")
	if strings.Count(updates, "waiting for Ethereum finality") != 2 || !strings.Contains(updates, "temporarily unavailable") || u.active != "" {
		t.Fatalf("withdrawal stage did not recover after the interruption: %s", updates)
	}
	if strings.Contains(u.String(), "waiting") || !strings.Contains(u.String(), "Withdrawal complete:") || f.approveCalls != 0 {
		t.Fatal("transient stages entered history or recovery authorized a transaction")
	}
}

func TestGuidedWithdrawalClearsProgressBeforeConsent(t *testing.T) {
	f := &withdrawalWizardFixture{}
	u := &recordingSetupDisplay{fundingWizardUI: fundingWizardUI{answers: []string{withdrawalTestDestination}, confirmations: []bool{false}}}
	err := guidedWithdrawal(context.Background(), f, u, immediateWizardPoll)
	if err == nil || !strings.Contains(err.Error(), "declined") || u.promptDuringWait || u.active != "" || f.approveCalls != 0 {
		t.Fatalf("progress interfered with explicit consent: %v, %+v", err, u)
	}
}
