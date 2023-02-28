package util

const (
	NsaCisaCheckType   = "nsa-cisa"
	charset            = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	ComplianceScan     = "compliance"
	ComplianceScanLogs = "compliance-scan-logs"
	StatusAlarm        = "alarm"
	StatusOk           = "ok"
	StatusInfo         = "info"
	StatusSkip         = "skip"
	StatusError        = "error"
)

type Config struct {
	ManagementConsoleUrl      string `json:"management_console_url,omitempty"`
	ManagementConsolePort     string `json:"management_console_port,omitempty"`
	DeepfenceKey              string `json:"deepfence_key,omitempty"`
	ComplianceCheckType       string `json:"compliance_check_type,omitempty"`
	ScanId                    string `json:"scan_id,omitempty"`
	NodeId                    string `json:"node_id,omitempty"`
	NodeName                  string `json:"node_name,omitempty"`
	ComplianceResultsFilePath string
	ComplianceStatusFilePath  string
}

type ComplianceDoc struct {
	Type                string `json:"type"`
	Timestamp           string `json:"@timestamp"`
	Masked              bool   `json:"masked"`
	NodeType            string `json:"node_type"`
	TestCategory        string `json:"test_category"`
	TestNumber          string `json:"test_number"`
	TestInfo            string `json:"description"`
	RemediationScript   string `json:"remediation_script,omitempty"`
	RemediationAnsible  string `json:"remediation_ansible,omitempty"`
	RemediationPuppet   string `json:"remediation_puppet,omitempty"`
	TestRationale       string `json:"test_rationale"`
	TestSeverity        string `json:"test_severity"`
	TestDesc            string `json:"test_desc"`
	Status              string `json:"status"`
	ComplianceCheckType string `json:"compliance_check_type"`
	ScanId              string `json:"scan_id"`
	Resource            string `json:"resource"`
	Group               string `json:"group"`
}

type ComplianceSummary struct {
	Alarm                int     `json:"alarm"`
	Ok                   int     `json:"ok"`
	Info                 int     `json:"info"`
	Skip                 int     `json:"skip"`
	Error                int     `json:"error"`
	CompliancePercentage float32 `json:"compliance_percentage"`
}

type ComplianceTags struct {
	Benchmark string `json:"benchmark"`
	Category  string `json:"category"`
	Plugin    string `json:"plugin"`
	Service   string `json:"service"`
	Type      string `json:"type"`
}

type ComplianceControlResult struct {
	Reason     string `json:"reason"`
	Resource   string `json:"resource"`
	Status     string `json:"status"`
	Dimensions []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"dimensions"`
}

type ComplianceControl struct {
	Results     []ComplianceControlResult `json:"results"`
	ControlID   string                    `json:"control_id"`
	Description string                    `json:"description"`
	Severity    string                    `json:"severity"`
	Tags        ComplianceTags            `json:"tags"`
	Title       string                    `json:"title"`
}

type ComplianceGroup struct {
	GroupID     string         `json:"group_id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Tags        ComplianceTags `json:"tags"`
	Summary     struct {
		Status ComplianceSummary `json:"status"`
	} `json:"summary"`
	Groups   []ComplianceGroup   `json:"groups"`
	Controls []ComplianceControl `json:"controls"`
}
