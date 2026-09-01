module github.com/warden-project/warden

// Minimum supported Go version per ADR-0001. It is the floor for self-hosters
// building from source, so raising it is a decision to record in that ADR and in
// CONTRIBUTING.md — not something to accept because a `go get` suggested it.
// cmd/warden/gomod_test.go fails if this drifts.
//
// Holding the floor costs three pins. Go computes the main module's directive as the
// maximum over every dependency's, so a single dependency built for a newer toolchain
// raises it for everyone. `go get github.com/jackc/pgx/v5@latest` did exactly that,
// silently moving the floor to 1.25 and putting go.mod at odds with the two documents
// that state 1.23. The pins below are what hold the line; each names what it is
// standing in for.
go 1.23.0

require (
	github.com/jackc/pgx/v5 v5.7.4
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	golang.org/x/crypto v0.35.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/text v0.22.0 // indirect
)

require (
	cel.dev/cel-go v0.32.0
	cel.dev/expr v0.25.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/exp v0.0.0-20240823005443-9b4947da3948 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)
