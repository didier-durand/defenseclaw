package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ToolInspectRequest is the payload for POST /api/v1/inspect/tool.
// A single endpoint handles both general tool policy checks and message
// content inspection — the handler branches on the Tool field.
type ToolInspectRequest struct {
	Tool      string          `json:"tool"`
	Args      json.RawMessage `json:"args,omitempty"`
	Content   string          `json:"content,omitempty"`
	Direction string          `json:"direction,omitempty"`
}

// ToolInspectVerdict is the response from the inspect endpoint.
type ToolInspectVerdict struct {
	Action          string        `json:"action"`
	Severity        string        `json:"severity"`
	Confidence      float64       `json:"confidence"`
	Reason          string        `json:"reason"`
	Findings        []string      `json:"findings"`
	DetailedFindings []RuleFinding `json:"detailed_findings,omitempty"`
	Mode            string        `json:"mode"`
}

// inspectToolPolicy runs all rule categories against the tool args.
// No tool-name gating — every pattern fires on every tool.
func (a *APIServer) inspectToolPolicy(req *ToolInspectRequest) *ToolInspectVerdict {
	argsStr := string(req.Args)
	toolName := req.Tool

	ruleFindings := ScanAllRules(argsStr, toolName)

	if len(ruleFindings) == 0 {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	severity := HighestSeverity(ruleFindings)
	confidence := HighestConfidence(ruleFindings, severity)

	action := "alert"
	if severity == "HIGH" || severity == "CRITICAL" {
		action = "block"
	}

	reasons := make([]string, 0, minInt(len(ruleFindings), 5))
	for i, f := range ruleFindings {
		if i >= 5 {
			break
		}
		reasons = append(reasons, f.RuleID+":"+f.Title)
	}

	return &ToolInspectVerdict{
		Action:           action,
		Severity:         severity,
		Confidence:       confidence,
		Reason:           fmt.Sprintf("matched: %s", strings.Join(reasons, ", ")),
		Findings:         FindingStrings(ruleFindings),
		DetailedFindings: ruleFindings,
	}
}

// inspectMessageContent scans outbound message content for secrets, PII,
// and data exfiltration patterns. Uses the same rule engine.
func (a *APIServer) inspectMessageContent(req *ToolInspectRequest) *ToolInspectVerdict {
	content := req.Content
	if content == "" {
		var parsed map[string]interface{}
		if err := json.Unmarshal(req.Args, &parsed); err == nil {
			if c, ok := parsed["content"].(string); ok {
				content = c
			} else if c, ok := parsed["body"].(string); ok {
				content = c
			}
		}
	}

	if content == "" {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	// Outbound messages get the full scan — tool name "message" for context
	ruleFindings := ScanAllRules(content, "message")

	if len(ruleFindings) == 0 {
		return &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	}

	severity := HighestSeverity(ruleFindings)
	confidence := HighestConfidence(ruleFindings, severity)

	// Outbound messages with any findings default to block —
	// content is about to leave the system boundary.
	action := "block"
	if severity == "LOW" {
		action = "alert"
	}

	reasons := make([]string, 0, minInt(len(ruleFindings), 5))
	for i, f := range ruleFindings {
		if i >= 5 {
			break
		}
		reasons = append(reasons, f.RuleID+":"+f.Title)
	}

	return &ToolInspectVerdict{
		Action:           action,
		Severity:         severity,
		Confidence:       confidence,
		Reason:           fmt.Sprintf("matched: %s", strings.Join(reasons, ", ")),
		Findings:         FindingStrings(ruleFindings),
		DetailedFindings: ruleFindings,
	}
}

func (a *APIServer) handleInspectTool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ToolInspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Tool == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tool is required"})
		return
	}

	t0 := time.Now()

	var verdict *ToolInspectVerdict

	if strings.ToLower(req.Tool) == "message" && (req.Content != "" || req.Direction == "outbound") {
		verdict = a.inspectMessageContent(&req)
	} else {
		verdict = a.inspectToolPolicy(&req)
	}

	mode := "observe"
	if a.scannerCfg != nil {
		mode = a.scannerCfg.Guardrail.Mode
	}
	if mode == "" {
		mode = "observe"
	}
	verdict.Mode = mode

	elapsed := time.Since(t0)

	var auditAction string
	switch verdict.Action {
	case "block":
		auditAction = "inspect-tool-block"
	case "alert":
		auditAction = "inspect-tool-alert"
	default:
		auditAction = "inspect-tool-allow"
	}
	_ = a.logger.LogAction(auditAction, req.Tool,
		fmt.Sprintf("severity=%s confidence=%.2f reason=%s elapsed=%s mode=%s",
			verdict.Severity, verdict.Confidence, verdict.Reason, elapsed, mode))

	a.writeJSON(w, http.StatusOK, verdict)
}
