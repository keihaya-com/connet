.PHONY: all build test

default: all

all: build test

build:
	go install -v github.com/keihaya-com/connet/cmd/... 

test:
	go test -cover -timeout 10s ./...

gen:
	fd --extension ".pb.go" . --exec-batch rm {}
	protoc --proto_path=pb/ --proto_path=pbs/ --proto_path=pbc/ --go_opt=module=github.com/keihaya-com/connet --go_out=./ pb/*.proto pbs/*.proto pbc/*.proto

.PHONY: run-server run-client run-sws
run-server: all
	connet-server -debug -auth xxyxx -server-cert .direnv/localhost/cert.pem -server-key .direnv/localhost/key.pem

run-client: all
	connet -debug -auth xxyxx -listen-name sws -listen-target ":8080" -connect-name sws -connect-source ":9999" -ca-cert .direnv/minica.pem -ca-key .direnv/minica-key.pem 

run-sws:
	static-web-server --port 8080 --root . --directory-listing

.PHONY: update-go update-nix

update-go:
	go get -u ./...
	go mod tidy

update-nix:
	nix flake update
