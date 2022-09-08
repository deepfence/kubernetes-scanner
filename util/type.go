package util

const (
	CloudProviderAWS            = "aws"
	CloudProviderGCP            = "gcp"
	CloudProviderAzure          = "azure"
	ModeLocal                   = "local"
	ModeService                 = "service"
	JsonOutput                  = "json"
	TableOutput                 = "table"
	NodeTypeCloudProvider       = "cloud_provider"
	NodeTypeCloudAccount        = "cloud_account"
	charset                     = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	ComplianceScanIndexName     = "compliance"
	ComplianceScanLogsIndexName = "compliance-scan-logs"
	StatusAlarm                 = "alarm"
	StatusOk                    = "ok"
	StatusInfo                  = "info"
	StatusSkip                  = "skip"
	StatusError                 = "error"
)

type Config struct {
	Mode                  string `json:"mode,omitempty"`
	Output                string `json:"output,omitempty"`
	Quiet                 bool   `json:"quiet,omitempty"`
	ManagementConsoleUrl  string `json:"management_console_url,omitempty"`
	ManagementConsolePort string `json:"management_console_port,omitempty"`
	DeepfenceKey          string `json:"deepfence_key,omitempty"`
	ComplianceCheckType   string `json:"compliance_check_type,omitempty"`
	ComplianceBenchmark   string `json:"compliance_benchmark,omitempty"`
	CloudProvider         string `json:"cloud_provider,omitempty"`
	ScanId                string `json:"scan_id,omitempty"`
	NodeId                string `json:"node_id,omitempty"`
	NodeName              string `json:"node_name,omitempty"`
	HttpServerRequired    bool
	Token                 string
}

type ComplianceDoc struct {
	Type                  string `json:"type"`
	TimeStamp             int64  `json:"time_stamp"`
	Timestamp             string `json:"@timestamp"`
	Masked                string `json:"masked"`
	NodeId                string `json:"node_id"`
	NodeType              string `json:"node_type"`
	KubernetesClusterName string `json:"kubernetes_cluster_name"`
	KubernetesClusterId   string `json:"kubernetes_cluster_id"`
	NodeName              string `json:"node_name"`
	TestCategory          string `json:"test_category"`
	TestNumber            string `json:"test_number"`
	TestInfo              string `json:"description"`
	RemediationScript     string `json:"remediation_script,omitempty"`
	RemediationAnsible    string `json:"remediation_ansible,omitempty"`
	RemediationPuppet     string `json:"remediation_puppet,omitempty"`
	TestRationale         string `json:"test_rationale"`
	TestSeverity          string `json:"test_severity"`
	TestDesc              string `json:"test_desc"`
	Status                string `json:"status"`
	ComplianceCheckType   string `json:"compliance_check_type"`
	ScanId                string `json:"scan_id"`
	ComplianceNodeType    string `json:"compliance_node_type"`
	Resource              string `json:"resource"`
	Group                 string `json:"group"`
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

type ScansResponse struct {
	Data PendingScans `json:"data"`
}

type PendingScanMap map[string]PendingScan

type PendingScans struct {
	Scans   PendingScanMap `json:"scans"`
	Refresh string         `json:"refresh"`
}

type PendingScan struct {
	ScanId    string   `json:"scan_id"`
	AccountId string   `json:"account_id"`
	ScanType  string   `json:"scan_type"`
	Controls  []string `json:"controls"`
}
