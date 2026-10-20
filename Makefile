# peephole — privacy-conformance harness for Horizen Vela apps.
TINYGO ?= tinygo
NOVA   := third_party/vela-nova/runtime/wasm-go
SIMPLE := third_party/vela/app/simple

.PHONY: all vela apps build test check demo clean

all: build

## vela: fetch the pinned Vela + vela-nova sources and install the test shim.
vela:
	bash ./scripts/fetch-vela.sh

## apps: compile the reference WASM apps (needs TinyGo v0.39.0 and `make vela`).
apps: apps/nova.wasm apps/tipjar.wasm

apps/nova.wasm: $(NOVA)
	@mkdir -p apps
	cd $(NOVA) && $(TINYGO) build -o $(CURDIR)/apps/nova.wasm -target=wasi .

apps/tipjar.wasm: examples/tipjar
	@mkdir -p apps
	cd examples/tipjar && $(TINYGO) build -o $(CURDIR)/apps/tipjar.wasm -target=wasi .

## build: compile the peephole binary.
build:
	go build -o bin/peephole ./cmd/peephole

## test: unit tests (fast) + integration test (needs apps/nova.wasm).
test:
	go test ./...

## check: run the full check suite against the reference payments app.
check: build apps/nova.wasm
	./bin/peephole -policy specs/nova.json -app apps/nova.wasm -scenario nova

## demo: show a leaky example app failing, then its hardened fix passing.
demo: build apps/tipjar.wasm
	-./bin/peephole -policy specs/tipjar-leaky.json    -app apps/tipjar.wasm -scenario tipjar-leaky
	./bin/peephole  -policy specs/tipjar-hardened.json -app apps/tipjar.wasm -scenario tipjar-hardened

clean:
	rm -rf bin apps
