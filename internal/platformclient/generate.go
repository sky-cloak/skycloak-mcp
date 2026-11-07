// Package platformclient is a second generated API client, built from the
// committed openapi.yaml by oapi-codegen. Do not edit platformclient.gen.go by
// hand; run `make generate` after updating openapi.yaml.
//
// openapi.yaml is the public copy of the spec: every /v1/staff/* path is
// removed at its source, and the sync refuses a copy that still has one.
// SOURCE_COMMIT records the main commit of the spec repository the copy was
// taken from, so a sync follows commits on main rather than release tags.
package platformclient

//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config=config.yaml openapi.yaml
