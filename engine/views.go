package engine

import (
	"math/big"

	ethCommon "github.com/ethereum/go-ethereum/common"
)

// AppEventView is an unencrypted application event as the chain sees it.
type AppEventView struct {
	Subtype [32]byte
	Data    []byte
}

// WithdrawalView is an on-chain withdrawal (token, destination, amount) — all public.
type WithdrawalView struct {
	Token  ethCommon.Address
	To     ethCommon.Address
	Amount *big.Int
}
