package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// UnreachableCluster names a cluster a fleet-wide call could not read.
//
// Reported rather than dropped. A fleet question is usually asked about posture
// ("which realms still allow self-registration"), and a silently partial answer
// under-reports, which is the direction that gets someone hurt. The caller is
// told the answer is incomplete and exactly which cluster is missing.
type UnreachableCluster struct {
	ClusterID   string `json:"cluster_id"`
	ClusterName string `json:"cluster_name,omitempty"`
	Error       string `json:"error"`
}

// fleetTarget is one cluster a fan-out call should visit.
type fleetTarget struct {
	id   string
	name string
}

// fleetTargets resolves the clusters a call should cover. A cluster_id names
// exactly one; omitting it means the whole workspace.
//
// Failing to list the clusters is fatal: without the list we do not know the
// fleet, and answering from a fleet we could not enumerate is a guess.
func fleetTargets(ctx context.Context, api API, clusterID string) ([]fleetTarget, error) {
	if clusterID != "" {
		return []fleetTarget{{id: clusterID}}, nil
	}
	clusters, err := api.ListClusters(ctx, skycloak.ListClustersParams{})
	if err != nil {
		return nil, fmt.Errorf("cluster_id was omitted, so every cluster in the workspace had to be listed, and that failed: %w", err)
	}
	out := make([]fleetTarget, 0, len(clusters))
	for _, c := range clusters {
		out = append(out, fleetTarget{id: c.ID, name: c.Name})
	}
	return out, nil
}

// fleetNote renders the incompleteness warning for a fan-out result. Empty when
// every cluster was read.
func fleetNote(unreachable []UnreachableCluster) string {
	if len(unreachable) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nIncomplete: could not read ")
	for i, u := range unreachable {
		if i > 0 {
			b.WriteString(", ")
		}
		name := u.ClusterName
		if name == "" {
			name = u.ClusterID
		}
		fmt.Fprintf(&b, "%s (%s)", name, u.Error)
	}
	b.WriteString(". Treat this as a partial answer; those clusters are unaccounted for.")
	return b.String()
}

// fleetHeader labels a row's cluster when a call covered more than one.
func fleetHeader(t fleetTarget, multi bool) string {
	if !multi {
		return ""
	}
	if t.name != "" {
		return fmt.Sprintf("[%s] ", t.name)
	}
	return fmt.Sprintf("[%s] ", t.id)
}
