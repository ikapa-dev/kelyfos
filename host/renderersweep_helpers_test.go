package main

import (
	"os"

	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

func sweepSource(name string) (string, error) {
	b, err := os.ReadFile(name)
	return string(b), err
}

// typeConstValue maps a `recorder.TypeX` identifier to its value. Written out
// because Go has no runtime reflection over constants; the sweep's own
// completeness check uses it, and a constant added to recorder without a row
// here is reported rather than silently skipped.
func typeConstValue(name string) (string, bool) {
	v, ok := map[string]string{
		"recorder.TypeSessionStart":       recorder.TypeSessionStart,
		"recorder.TypeSessionReady":       recorder.TypeSessionReady,
		"recorder.TypeSessionEnd":         recorder.TypeSessionEnd,
		"recorder.TypeCommandStart":       recorder.TypeCommandStart,
		"recorder.TypeCommandOutput":      recorder.TypeCommandOutput,
		"recorder.TypeCommandExit":        recorder.TypeCommandExit,
		"recorder.TypeFileWrite":          recorder.TypeFileWrite,
		"recorder.TypeEgressAttempt":      recorder.TypeEgressAttempt,
		"recorder.TypeSecretUse":          recorder.TypeSecretUse,
		"recorder.TypeSecretWithheld":     recorder.TypeSecretWithheld,
		"recorder.TypeSecretScrubbed":     recorder.TypeSecretScrubbed,
		"recorder.TypeResourceOOM":        recorder.TypeResourceOOM,
		"recorder.TypeResourceTimeout":    recorder.TypeResourceTimeout,
		"recorder.TypeResourceSummary":    recorder.TypeResourceSummary,
		"recorder.TypeTeamMessage":        recorder.TypeTeamMessage,
		"recorder.TypeTeamRefused":        recorder.TypeTeamRefused,
		"recorder.TypeTeamStore":          recorder.TypeTeamStore,
		"recorder.TypeTeamSpawn":          recorder.TypeTeamSpawn,
		"recorder.TypeMCPHostCall":        recorder.TypeMCPHostCall,
		"recorder.TypeMCPHostResult":      recorder.TypeMCPHostResult,
		"recorder.TypePluginCall":         recorder.TypePluginCall,
		"recorder.TypePluginCrash":        recorder.TypePluginCrash,
		"recorder.TypeSessionPause":       recorder.TypeSessionPause,
		"recorder.TypeSessionResume":      recorder.TypeSessionResume,
		"recorder.TypeRunReview":          recorder.TypeRunReview,
		"recorder.TypeShellStart":         recorder.TypeShellStart,
		"recorder.TypeShellEnd":           recorder.TypeShellEnd,
		"recorder.TypeForwardAccept":      recorder.TypeForwardAccept,
		"recorder.TypeSessionPolicy":      recorder.TypeSessionPolicy,
		"recorder.TypeTeamTopology":       recorder.TypeTeamTopology,
		"recorder.TypeSessionErasure":     recorder.TypeSessionErasure,
		"recorder.TypeChannelRefused":     recorder.TypeChannelRefused,
		"recorder.TypeSecretUnscrubbable": recorder.TypeSecretUnscrubbable,
		"recorder.TypeVMMAction":          recorder.TypeVMMAction,
	}[name]
	return v, ok
}
