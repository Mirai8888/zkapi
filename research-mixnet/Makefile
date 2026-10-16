.PHONY: test build demo vet compare

# The upstream algorithm registry requires CGO and a C compiler, even though
# this experiment explicitly selects X25519 (no post-quantum claim).
test:
	go test -race -count=1 ./...
vet:
	go vet ./...
build:
	go build -trimpath -o bin/research-mixnet ./cmd/research-mixnet
demo:
	go run ./cmd/research-mixnet demo
compare: build
	./bin/research-mixnet compare --output-dir evidence/process-comparison
