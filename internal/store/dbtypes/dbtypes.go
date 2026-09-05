// Package dbtypes holds the Go types sqlc maps Warden's non-scalar columns onto.
//
// It exists because sqlc's `overrides` only accept a named type from an importable
// package, never an anonymous one. Keeping it a leaf package — it imports nothing —
// means the generated code can depend on it without a cycle back into store.
package dbtypes

// JSONMap is a jsonb column holding an object: resource and subject attributes, role
// constraints, an attribute schema, a UI binding's clause set.
//
// It is a named map type rather than a struct wrapper on purpose. Go makes a named
// type and its unnamed underlying type mutually assignable, so a caller holding a
// plain map[string]any passes it straight to a generated method, and a scanned value
// is used as a plain map — the override changes the generated signatures and not one
// line of the code that calls them. pgx's JSONCodec marshals and unmarshals it with
// encoding/json, which is what the hand-written queries already relied on.
type JSONMap map[string]any
