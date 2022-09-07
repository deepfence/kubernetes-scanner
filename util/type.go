package util

const (
	CloudProviderAWS                 = "aws"
	CloudProviderGCP                 = "gcp"
	CloudProviderAzure               = "azure"
	ModeLocal                        = "local"
	ModeService                      = "service"
	JsonOutput                       = "json"
	TableOutput                      = "table"
	NodeTypeCloudProvider            = "cloud_provider"
	NodeTypeCloudAccount             = "cloud_account"
	charset                          = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	CloudComplianceScanIndexName     = "cloud-compliance-scan"
	CloudComplianceScanLogsIndexName = "cloud-compliance-scan-logs"
	StatusAlarm                      = "alarm"
	StatusOk                         = "ok"
	StatusInfo                       = "info"
	StatusSkip                       = "skip"
	StatusError                      = "error"
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
	Timestamp           string `json:"@timestamp"`
	Count               int    `json:"count,omitempty"`
	Reason              string `json:"reason"`
	Resource            string `json:"resource"`
	Status              string `json:"status"`
	Region              string `json:"region"`
	AccountID           string `json:"account_id"`
	Group               string `json:"group"`
	Service             string `json:"service"`
	Title               string `json:"title"`
	ComplianceCheckType string `json:"compliance_check_type"`
	CloudProvider       string `json:"cloud_provider"`
	NodeName            string `json:"node_name"`
	NodeID              string `json:"node_id"`
	ScanID              string `json:"scan_id"`
	Masked              string `json:"masked"`
	Type                string `json:"type"`
	ControlID           string `json:"control_id"`
	Description         string `json:"description"`
	Severity            string `json:"severity"`
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
