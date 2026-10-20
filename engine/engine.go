// Package engine runs a Vela WASM app through the real Vela executor
// (pkg/executor.StatelessExecutor with the Wasmtime runtime) and records,
// for every request, exactly what leaves the enclave.
package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/HorizenOfficial/vela/pkg/common"
	cryptotypes "github.com/HorizenOfficial/vela/pkg/common/crypto"
	velacrypto "github.com/HorizenOfficial/vela/pkg/crypto"
	"github.com/HorizenOfficial/vela/pkg/executor"
	vela_wasm "github.com/HorizenOfficial/vela/pkg/wasm"
	ethCommon "github.com/ethereum/go-ethereum/common"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"
)

// SubtypeN mirrors executor.DefaultSubtypeN: the size of each user's tag set.
const SubtypeN = executor.DefaultSubtypeN

// User is a Vela user: an Ethereum address, the P-521 key events are
// encrypted to, and (optionally) the seed registered for private subtypes.
type User struct {
	Name string
	Addr ethCommon.Address
	Key  *cryptotypes.PrivateKeyP521
	Seed []byte // 65 bytes, nil if the user registered no seed
}

// NewUser derives a user the way the vela-nova wallet does: a secp256k1
// account, a P-521 key, and seed = sign(keccak("subtype-key-v1")).
func NewUser(name string, withSeed bool) (*User, error) {
	sk, err := ethCrypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	pk, err := velacrypto.GeneratePrivateKeyP521()
	if err != nil {
		return nil, err
	}
	u := &User{Name: name, Addr: ethCrypto.PubkeyToAddress(sk.PublicKey), Key: pk}
	if withSeed {
		seed, err := ethCrypto.Sign(ethCrypto.Keccak256([]byte(executor.SubtypeKeyMessage)), sk)
		if err != nil {
			return nil, err
		}
		u.Seed = seed
	}
	return u, nil
}

// Subtypes returns the user's full tag set (what their wallet scans for).
func (u *User) Subtypes() [][32]byte {
	if u.Seed == nil {
		return nil
	}
	return executor.AllSubtypes(u.Seed, SubtypeN)
}

// Request is one user action as it is submitted on-chain.
type Request struct {
	Sender      *User
	Type        common.RequestType // Process, Deanonymize or AssociateKey
	Payload     []byte             // plaintext JSON for Process/Deanonymize
	Token       ethCommon.Address  // deposit token (zero = ETH)
	Deposit     *big.Int           // public deposit amount, nil or 0 for none
	MaxFeeValue *big.Int
}

// UserEvent is an encrypted event as emitted by ProcessorEndpoint.UserEvent.
type UserEvent struct {
	Subtype   [32]byte
	CipherLen int
	// Operator-only: the executor hands UserID to the manager in clear.
	UserID ethCommon.Address
	// Ground truth for the harness (never visible to anyone but the owner).
	Plaintext []byte
}

// Observation is everything one request makes visible outside the enclave.
type Observation struct {
	// Public on-chain (ProcessorEndpoint calldata and events).
	Sender       ethCommon.Address
	RequestType  common.RequestType
	PayloadLen   int // length of the encrypted payload in submitRequest calldata
	DepositToken ethCommon.Address
	Deposit      *big.Int
	OK           bool
	ErrorCode    uint8
	ErrorMsg     string
	UserEvents   []UserEvent
	AppEvents    []common.AppEvent
	Withdrawals  []common.Withdrawal
	Fee          *big.Int
	Refund       *big.Int
	// Operator view (host running the manager): encrypted state size and
	// guest log lines routed to the network logger.
	StateLen  int
	GuestLogs []string
	// HarnessErr is set when the executor refused the request outright
	// (no on-chain result would be posted).
	HarnessErr string
}

// World is one deployed instance of an app.
type World struct {
	exec    *executor.StatelessExecutor
	rt      *vela_wasm.WasmtimeRuntime
	log     *CaptureLogger
	wasm    []byte
	appID   common.ApplicationIdType
	state   *common.ApplicationState
	Users   []*User
	encPub  *cryptotypes.PublicKeyP521
	History []Observation
}

var appIDctr uint64

func nextAppID() uint64 { return atomic.AddUint64(&appIDctr, 1) }

var rtOnce sync.Once
var sharedRT *vela_wasm.WasmtimeRuntime
var sharedLog *CaptureLogger

// runtime returns a process-wide Wasmtime runtime; compiling the module once
// keeps thousands of paired runs fast. Guest logs are captured per request.
func runtime() (*vela_wasm.WasmtimeRuntime, *CaptureLogger) {
	rtOnce.Do(func() {
		sharedLog = NewCaptureLogger()
		sharedRT = vela_wasm.NewWasmtimeRuntime(sharedLog, 4)
	})
	return sharedRT, sharedLog
}

// NewWorld deploys the module with the given constructor params and
// registers every user's key (and seed, when they have one).
func NewWorld(wasm []byte, deployParams []byte, users []*User) (*World, error) {
	rt, log := runtime()
	ex, err := executor.NewPeepholeExecutor(rt, log)
	if err != nil {
		return nil, err
	}
	// The Wasmtime runtime is shared across Worlds and caches modules per app
	// id, so every World gets a fresh id to stay isolated.
	w := &World{exec: ex, rt: rt, log: log, wasm: wasm, appID: common.NewApplicationId(nextAppID()), Users: users,
		encPub: ex.PeepholeCommunicationPublicKey()}

	sum := sha256.Sum256(wasm)
	sha := hex.EncodeToString(sum[:])
	artifact, err := common.BuildArtifactID(sha)
	if err != nil {
		return nil, err
	}
	desc := common.DeployDescriptor{Mode: common.DeployModeArtifactRef, ArtifactID: artifact, WasmSHA256: sha}
	if len(deployParams) > 0 {
		desc.ConstructorParams = deployParams
	}
	payload, err := json.Marshal(desc)
	if err != nil {
		return nil, err
	}
	req := w.baseRequest(common.Deploy, payload, big.NewInt(1_000_000))
	up, st, err := ex.HandleDeployApp(context.Background(), req, nil, wasm)
	if err != nil {
		return nil, fmt.Errorf("deploy: %w", err)
	}
	if up.ErrorCode != 0 || st == nil {
		return nil, fmt.Errorf("deploy failed: code %d: %s", up.ErrorCode, up.ErrorMsg)
	}
	w.state = st
	for _, u := range users {
		if err := w.register(u); err != nil {
			return nil, err
		}
	}
	return w, nil
}

func (w *World) baseRequest(t common.RequestType, payload []byte, maxFee *big.Int) *common.Request {
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &common.Request{
		ApplicationID: w.appID,
		RequestID:     common.RequestIdType(id),
		RequestType:   t,
		Payload:       payload,
		Timestamp:     common.NewBig(1_760_000_000),
		AssetAmount:   common.NewBig(0),
		MaxFeeValue:   common.ToBig(maxFee),
	}
}

// register submits ASSOCIATEKEY: 133-byte public key, plus the seed encrypted
// to the enclave (226 bytes total) when the user has one.
func (w *World) register(u *User) error {
	payload := append([]byte{}, u.Key.PublicKey().Bytes()...)
	if u.Seed != nil {
		enc, err := velacrypto.Encrypt(u.Key, w.encPub, u.Seed)
		if err != nil {
			return err
		}
		payload = append(payload, enc...)
	}
	req := w.baseRequest(common.AssociateKey, payload, big.NewInt(1_000_000))
	req.Sender = u.Addr
	up, st, _, err := w.exec.HandleProcessRequest(context.Background(), req, w.state, w.wasm)
	if err != nil {
		return fmt.Errorf("register %s: %w", u.Name, err)
	}
	if up.ErrorCode != 0 {
		return fmt.Errorf("register %s: code %d %s", u.Name, up.ErrorCode, up.ErrorMsg)
	}
	w.state = st
	return nil
}

// Submit runs one request and returns what it exposes.
func (w *World) Submit(r Request) Observation {
	maxFee := r.MaxFeeValue
	if maxFee == nil {
		maxFee = big.NewInt(1_000_000)
	}
	var payload []byte
	if len(r.Payload) > 0 {
		enc, err := velacrypto.Encrypt(r.Sender.Key, w.encPub, r.Payload)
		if err != nil {
			return Observation{HarnessErr: err.Error()}
		}
		payload = enc
	}
	req := w.baseRequest(r.Type, payload, maxFee)
	req.Sender = r.Sender.Addr
	req.TokenAddress = r.Token
	dep := r.Deposit
	if dep == nil {
		dep = big.NewInt(0)
	}
	req.AssetAmount = common.ToBig(dep)

	obs := Observation{Sender: r.Sender.Addr, RequestType: r.Type, PayloadLen: len(payload),
		DepositToken: r.Token, Deposit: new(big.Int).Set(dep)}

	w.log.Reset()
	up, st, _, err := w.exec.HandleProcessRequest(context.Background(), req, w.state, w.wasm)
	w.log.Settle()
	obs.GuestLogs = w.log.GuestLines()
	if err != nil {
		obs.HarnessErr = err.Error()
		w.History = append(w.History, obs)
		return obs
	}
	obs.OK = up.ErrorCode == 0
	obs.ErrorCode = up.ErrorCode
	obs.ErrorMsg = up.ErrorMsg
	obs.AppEvents = up.AppEvents
	obs.Withdrawals = up.Withdrawals
	if up.ApplicationFee != nil {
		obs.Fee = up.ApplicationFee.ToInt()
	}
	if up.RefundAmount != nil {
		obs.Refund = up.RefundAmount.ToInt()
	}
	for _, ev := range up.Events {
		ue := UserEvent{Subtype: ev.EventSubType, CipherLen: len(ev.EncryptedData), UserID: ev.UserID}
		if u := w.user(ev.UserID); u != nil {
			if pt, err := velacrypto.Decrypt(w.encPub, u.Key, ev.EncryptedData); err == nil {
				ue.Plaintext = pt
			}
		}
		obs.UserEvents = append(obs.UserEvents, ue)
	}
	if st != nil {
		w.state = st
	}
	if w.state != nil {
		obs.StateLen = len(w.state.EncryptedState)
	}
	w.History = append(w.History, obs)
	return obs
}

func (w *World) user(a ethCommon.Address) *User {
	for _, u := range w.Users {
		if u.Addr == a {
			return u
		}
	}
	return nil
}

// UserByName finds a user by name.
func (w *World) UserByName(n string) *User {
	for _, u := range w.Users {
		if u.Name == n {
			return u
		}
	}
	return nil
}

// ShortErr trims the noise Vela prepends to guest errors.
func ShortErr(s string) string {
	return strings.TrimPrefix(s, "failed to process request: ")
}
