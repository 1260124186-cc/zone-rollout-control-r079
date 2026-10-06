package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"time"
)

func ActivatePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanDraft {
		return InvalidState("plan can be activated only from draft", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	if plan.LatestRevisionID == "" {
		return InvalidState("plan needs a zone revision before activation", map[string]any{
			"plan_id": plan.ID,
		})
	}
	plan.State = PlanActive
	plan.ActivatedAt = timePointer(now.UTC())
	plan.Version++
	return nil
}

func CompletePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanActive {
		return InvalidState("plan can be completed only from active", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	plan.State = PlanCompleted
	plan.CompletedAt = timePointer(now.UTC())
	plan.Version++
	return nil
}

func LeaseReplayKey(planID string, requestKey string) string {
	return planID + "\x1f" + requestKey
}

func EnsureLeaseReplays(state *State) {
	if state == nil {
		return
	}
	if state.LeaseReplays == nil {
		state.LeaseReplays = make(map[string]LeaseReplay)
	}
}

func RecordLeaseReplay(state *State, planID string, requestKey string, groupID string) {
	EnsureLeaseReplays(state)
	state.LeaseReplays[LeaseReplayKey(planID, requestKey)] = LeaseReplay{
		PlanID:     planID,
		RequestKey: requestKey,
		GroupID:    groupID,
	}
}

func LookupLeaseReplay(state *State, planID string, requestKey string) (LeaseReplay, bool) {
	if state == nil || state.LeaseReplays == nil {
		return LeaseReplay{}, false
	}
	entry, ok := state.LeaseReplays[LeaseReplayKey(planID, requestKey)]
	if !ok || entry.GroupID == "" {
		return LeaseReplay{}, false
	}
	return entry, true
}

func LeaseReplayFor(state *State, planID string, requestKey string) (LeaseGroup, bool) {
	entry, ok := LookupLeaseReplay(state, planID, requestKey)
	if !ok {
		return LeaseGroup{}, false
	}
	group, ok := state.LeaseGroups[entry.GroupID]
	if !ok {
		return LeaseGroup{}, false
	}
	return group, true
}

func RebuildLeaseReplays(state *State) {
	if state == nil {
		return
	}
	rebuilt := make(map[string]LeaseReplay, len(state.LeaseGroups))
	for _, group := range state.LeaseGroups {
		if group.RequestKey == "" {
			continue
		}
		rebuilt[LeaseReplayKey(group.PlanID, group.RequestKey)] = LeaseReplay{
			PlanID:     group.PlanID,
			RequestKey: group.RequestKey,
			GroupID:    group.ID,
		}
	}
	state.LeaseReplays = rebuilt
}

func LeaseFingerprint(planID string, input LeaseInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%s|%d|%d",
		planID,
		input.RequestKey,
		input.Region,
		input.LeaseSeconds,
		input.MaxNodes,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func ProbeFingerprint(leaseID string, input ProbeInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%t|%d|%d|%s",
		leaseID,
		input.RequestKey,
		input.Success,
		input.ObservedSerial,
		input.LatencyMS,
		input.ObservedAt.UTC().Format(time.RFC3339Nano),
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func BuildAssessment(
	id string,
	plan RolloutPlan,
	revision ZoneRevision,
	probes []Probe,
	now time.Time,
) RolloutAssessment {
	reasons := make(map[string]struct{})
	if len(probes) == 0 {
		reasons["no_probes"] = struct{}{}
	}
	probeCount := len(probes)
	successCount := 0
	maximumLatency := 0
	nodes := make(map[string]struct{})
	for _, probe := range probes {
		nodes[probe.NodeID] = struct{}{}
		if probe.LatencyMS > maximumLatency {
			maximumLatency = probe.LatencyMS
		}
		if probe.Success {
			successCount++
			if probe.ObservedSerial != revision.Serial {
				reasons["serial_mismatch"] = struct{}{}
			}
		}
	}
	if len(nodes) < plan.ExpectedNodes {
		reasons["node_not_observed"] = struct{}{}
	}
	successRatio := 0.0
	if probeCount > 0 {
		successRatio = round(float64(successCount)/float64(probeCount), 6)
	}
	if successRatio < plan.MinimumSuccessRatio {
		reasons["success_ratio_below_minimum"] = struct{}{}
	}
	if maximumLatency > plan.MaximumLatencyMS {
		reasons["latency_limit_exceeded"] = struct{}{}
	}
	reasonList := make([]string, 0, len(reasons))
	for reason := range reasons {
		reasonList = append(reasonList, reason)
	}
	sort.Strings(reasonList)
	verdict := VerdictConsistent
	if len(reasonList) > 0 {
		verdict = VerdictReviewRequired
	}
	return RolloutAssessment{
		ID:               id,
		PlanID:           plan.ID,
		RevisionID:       revision.ID,
		Verdict:          verdict,
		Reasons:          reasonList,
		ProbeCount:       probeCount,
		SuccessCount:     successCount,
		SuccessRatio:     successRatio,
		MaximumLatencyMS: maximumLatency,
		CreatedAt:        now.UTC(),
	}
}

func round(value float64, places int) float64 {
	scale := math.Pow10(places)
	return math.Round(value*scale) / scale
}

func timePointer(value time.Time) *time.Time {
	return &value
}
