// tipjar is a tiny, self-authored Vela app used to demonstrate peephole:
// tippers send a private tip (amount + memo confidential) to a public jar.
// It has two modes, chosen at deploy time:
//
//	"leaky"    — the natural first implementation; peephole fails it.
//	"hardened" — amount padded to fixed width, memo receipt blinded with a
//	             per-app secret kept in encrypted state; peephole passes it.
//
// Same app, same scenario: the point is that peephole catches the leaks and
// then confirms the fix. This is our own code (MIT), not Horizen's.
package main

import (
	"encoding/binary"
	"encoding/json"

	"github.com/HorizenOfficial/vela-common-go/wasm/types"
	"github.com/HorizenOfficial/vela-common-go/wasm/utils"
	"golang.org/x/crypto/sha3"
)

type state struct {
	Mode     string            `json:"mode"`   // "leaky" | "hardened"
	Salt     string            `json:"salt"`   // per-app secret, never emitted
	Balances map[string]uint64 `json:"bal"`
}

type deployParams struct {
	Mode string `json:"mode"`
	Salt string `json:"salt"`
}

type tip struct {
	Amount uint64 `json:"amount"`
	Memo   string `json:"memo"`
}
type payload struct {
	Type string `json:"type"`
	Tip  *tip   `json:"tip,omitempty"`
}

//export deploy
func deploy(appId int64, pPtr *byte, pLen int32) *byte {
	var dp deployParams
	_ = json.Unmarshal([]byte(utils.PtrToString(pPtr, pLen)), &dp)
	if dp.Mode == "" {
		dp.Mode = "leaky"
	}
	st := state{Mode: dp.Mode, Salt: dp.Salt, Balances: map[string]uint64{}}
	b, _ := json.Marshal(st)
	return types.SerializeAndWriteResult(types.DeployResult{State: b, Fuel: types.NewUint256(5)})
}

//export load_module
func load_module(appId int64) *byte {
	st := state{Mode: "leaky", Balances: map[string]uint64{}}
	b, _ := json.Marshal(st)
	return types.SerializeAndWriteResult(types.LoadModuleResult{State: b, Fuel: types.NewUint256(5)})
}

//export deposit
func deposit(appId int64, senderPtr *byte, senderLen int32, tokenPtr *byte, tokenLen int32, valuePtr *byte, valueLen int32, statePtr *byte, stateLen int32) *byte {
	sender := types.PtrToAddress(senderPtr, senderLen)
	value := types.PtrToUint256(valuePtr, valueLen)
	var st state
	_ = json.Unmarshal([]byte(utils.PtrToString(statePtr, stateLen)), &st)
	if st.Balances == nil {
		st.Balances = map[string]uint64{}
	}
	// small balances only (demo); low byte of the value is enough
	vb := value.Bytes()
	var v uint64
	for _, c := range vb {
		v = v<<8 | uint64(c)
	}
	st.Balances[sender.Hex()] += v
	b, _ := json.Marshal(st)
	return types.SerializeAndWriteResult(types.DepositResult{State: b, Fuel: types.NewUint256(35)})
}

//export process_request
func process_request(appId int64, senderPtr *byte, senderLen int32, requestType int32, payloadPtr *byte, payloadLen int32, statePtr *byte, stateLen int32) *byte {
	sender := types.PtrToAddress(senderPtr, senderLen)
	var st state
	_ = json.Unmarshal([]byte(utils.PtrToString(statePtr, stateLen)), &st)
	var pl payload
	_ = json.Unmarshal([]byte(utils.PtrToString(payloadPtr, payloadLen)), &pl)
	if pl.Type != "tip" || pl.Tip == nil {
		return types.SerializeAndWriteResult(types.ProcessResult{Error: "unsupported"})
	}

	// The tipper's own encrypted receipt event carries the amount.
	amountField := encodeAmount(st.Mode, pl.Tip.Amount)
	evData, _ := json.Marshal(map[string]string{"type": "tip", "amount": amountField, "memo": pl.Tip.Memo})
	events := []types.PlainEvent{{UserID: *sender, Data: evData}}

	// Public receipt commitment over (memo, sender, amount), optionally blinded.
	receipt := commit(st.Mode, st.Salt, pl.Tip.Memo, *sender, pl.Tip.Amount)
	appEvents := []types.AppEvent{{EventSubType: receipt}}

	b, _ := json.Marshal(st)
	return types.SerializeAndWriteResult(types.ProcessResult{State: b, Events: events, AppEvents: appEvents, Fuel: types.NewUint256(50)})
}

// encodeAmount: leaky prints the minimal decimal (length tracks magnitude);
// hardened prints a fixed 20-digit zero-padded string (constant length).
func encodeAmount(mode string, amount uint64) string {
	if mode == "hardened" {
		return pad20(amount)
	}
	return itoa(amount)
}

// commit: leaky hashes a low-entropy tuple with no secret; hardened prepends the
// per-app salt (kept in encrypted state), so the receipt is not brute-forceable.
func commit(mode, salt, memo string, sender types.Address, amount uint64) [32]byte {
	h := sha3.NewLegacyKeccak256()
	if mode == "hardened" {
		h.Write([]byte(salt))
	}
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(memo)))
	h.Write(lp[:])
	h.Write([]byte(memo))
	h.Write(sender[:])
	var a8 [8]byte
	binary.BigEndian.PutUint64(a8[:], amount)
	h.Write(a8[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func pad20(v uint64) string {
	s := itoa(v)
	for len(s) < 20 {
		s = "0" + s
	}
	return s
}

func main() {}
