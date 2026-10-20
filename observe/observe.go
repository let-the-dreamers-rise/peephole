// Package observe projects a recorded run down to exactly what one audience
// can see, so a check can only use information that audience actually has.
package observe

import (
	"math/big"

	ethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/let-the-dreamers-rise/peephole/engine"
	"github.com/let-the-dreamers-rise/peephole/spec"
	"github.com/let-the-dreamers-rise/peephole/trace"
)

// VisibleEvent is a user-event as seen by an audience. Public sees only the
// 32-byte subtype and the ciphertext length. Operator additionally sees the
// recipient address the executor routes the event to.
type VisibleEvent struct {
	Subtype   [32]byte
	CipherLen int
	Recipient ethCommon.Address // set for Operator view only
}

// View is one step as one audience sees it.
type View struct {
	Label       string
	Audience    spec.Audience
	Sender      ethCommon.Address // request submitter (public on-chain)
	Deposit     *big.Int
	DepositTok  ethCommon.Address
	PayloadLen  int // encrypted payload size in submitRequest calldata
	OK          bool
	UserEvents  []VisibleEvent
	AppEvents   []engine.AppEventView
	Withdrawals []engine.WithdrawalView
	GuestLogs   []string // operator only
}

// Project reduces a step to what the given audience can observe.
func Project(st trace.Step, a spec.Audience) View {
	o := st.Obs
	v := View{Label: st.Label, Audience: a, Sender: o.Sender, Deposit: o.Deposit,
		DepositTok: o.DepositToken, PayloadLen: o.PayloadLen, OK: o.OK}
	for _, w := range o.Withdrawals {
		v.Withdrawals = append(v.Withdrawals, engine.WithdrawalView{
			Token: w.TokenAddress, To: w.DestinationAddress, Amount: w.Amount.ToInt()})
	}
	for _, e := range o.AppEvents {
		v.AppEvents = append(v.AppEvents, engine.AppEventView{Subtype: e.EventSubType, Data: e.Data})
	}
	for _, e := range o.UserEvents {
		ve := VisibleEvent{Subtype: e.Subtype, CipherLen: e.CipherLen}
		if a == spec.Operator {
			ve.Recipient = e.UserID
		}
		v.UserEvents = append(v.UserEvents, ve)
	}
	if a == spec.Operator {
		v.GuestLogs = o.GuestLogs
	}
	return v
}

// ProjectAll projects every step for one audience.
func ProjectAll(t *trace.Trace, a spec.Audience) []View {
	out := make([]View, len(t.Steps))
	for i, st := range t.Steps {
		out[i] = Project(st, a)
	}
	return out
}
