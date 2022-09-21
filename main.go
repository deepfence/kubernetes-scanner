package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/deepfence/kspm/util"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	quiet                 = flag.Bool("quiet", false, "Don't display any output in stdout")
	managementConsoleUrl  = flag.String("mgmt-console-url", "", "Deepfence Management Console URL")
	managementConsolePort = flag.Int("mgmt-console-port", 443, "Deepfence Management Console Port")
	deepfenceKey          = os.Getenv("DEEPFENCE_KEY")
	nodeId                = flag.String("node-id", "", "node-id of the cluster it is deployed in")
	debug                 = flag.Bool("debug", false, "set log level to debug")
)

const (
	MethodPost = "POST"
)

func main() {
	_, err := exec.Command("/bin/sh", "/home/deepfence/token.sh").CombinedOutput()
	if err != nil {
		logrus.Error(err)
	} else {
		logrus.Debug("Token generated successfully")
	}
	flag.Parse()

	customFormatter := new(logrus.TextFormatter)
	customFormatter.FullTimestamp = true
	customFormatter.DisableLevelTruncation = true
	customFormatter.PadLevelText = true
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.CallerPrettyfier = func(f *runtime.Frame) (string, string) {
		return "", path.Base(f.File) + ":" + strconv.Itoa(f.Line)
	}

	logrus.SetReportCaller(true)
	logrus.SetFormatter(customFormatter)
	if *debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	config := util.Config{
		Quiet:                 *quiet,
		ManagementConsoleUrl:  *managementConsoleUrl,
		ManagementConsolePort: strconv.Itoa(*managementConsolePort),
		DeepfenceKey:          *deepfenceKey,
		HttpServerRequired:    false,
		NodeId:                *nodeId,
	}
	config.Token, _ = util.GetApiAccessToken(config)
	logrus.Debug("Token generated success:{}", config.Token)
	fmt.Println("Token generated success:{}", config.Token)
	runServices(config)
}

func runServices(config util.Config) {
	ticker := time.NewTicker(1 * time.Minute / 2)
	for {
		select {
		case <-ticker.C:
			registerNodeId(config)
		}
	}
}

func registerNodeId(config util.Config) {
	registerNodePayload := `{"node_id": "` + config.NodeId + `", "node_name": "` + config.NodeId + `"}`
	resp, _, err := util.HttpRequest(MethodPost,
		"https://"+config.ManagementConsoleUrl+"/deepfence/v1.5/cloud_compliance/kubernetes",
		registerNodePayload, map[string]string{}, config)
	if err != nil {
		logrus.Error(err)
	}
	var scansResponse util.ScansResponse
	err = json.Unmarshal(resp, &scansResponse)
	if err != nil {
		logrus.Error(err)
	}
	pendingScans := make(map[string]util.PendingScan)
	for scanId, scanDetails := range scansResponse.Data.Scans {
		if _, ok := pendingScans[scanId]; !ok {
			pendingScans[scanId] = scanDetails
			err := SendScanStatustoConsole(scanId, "cis", "", "INPROGRESS", nil, config)

			if err != nil {
				logrus.Error(err)
			}
			scanResult, err := RunComplianceScan()
			if err != nil {
				err = SendScanStatustoConsole(scanId, "cis", err.Error(), "ERROR", nil, config)
				continue
			}
			config.ScanId = scanId
			//b, _ := json.Marshal(scanResult)
			//logrus.Error("scanResult:")
			//logrus.Error(string(b))
			complianceDocs, complianceSummary, err := ParseComplianceResults(scanResult, config)
			fmt.Println("Parsed Compliance Docs:")
			b, _ := json.Marshal(complianceDocs)
			fmt.Println(string(b))
			err = IngestComplianceResults(complianceDocs, config)
			if err != nil {
				logrus.Error(err)
			}
			extras := map[string]interface{}{
				"node_name":    config.NodeId,
				"node_id":      config.NodeId,
				"result":       complianceSummary,
				"total_checks": complianceSummary.Alarm + complianceSummary.Ok + complianceSummary.Info + complianceSummary.Skip + complianceSummary.Error,
			}
			err = SendScanStatustoConsole(config.ScanId, "cis", "", "COMPLETED", extras, config)
			if err != nil {
				logrus.Error(err)
			}
		}
	}
}

func RunComplianceScan() (util.ComplianceGroup, error) {
	tempFileName := fmt.Sprintf("/tmp/%s.json", util.RandomString(12))
	//defer os.Remove(tempFileName)
	spKubePath := "/opt/steampipe/steampipe-mod-kubernetes-compliance"
	cmd := fmt.Sprintf("cd %s && steampipe check --progress=false --output=none --export=%s benchmark.nsa_cisa_v1", spKubePath, tempFileName)
	stdOut, stdErr := exec.Command("bash", "-c", cmd).CombinedOutput()
	var complianceResults util.ComplianceGroup
	if _, err := os.Stat(tempFileName); errors.Is(err, os.ErrNotExist) {
		return complianceResults, fmt.Errorf("%s: %v", stdOut, stdErr)
	}
	tempFile, err := os.Open(tempFileName)
	if err != nil {
		return complianceResults, err
	}
	results, err := ioutil.ReadAll(tempFile)
	if err != nil {
		return complianceResults, err
	}
	err = json.Unmarshal(results, &complianceResults)
	if err != nil {
		return complianceResults, err
	}
	return complianceResults, nil
}

func SendScanStatustoConsole(scanId string, scanType string, scanMsg string, status string, extras map[string]interface{}, config util.Config) error {
	scanMsg = strings.Replace(scanMsg, "\n", " ", -1)
	scanLog := map[string]interface{}{
		"scan_id":                 scanId,
		"time_stamp":              util.GetIntTimestamp(),
		"@timestamp":              util.GetDatetimeNow(),
		"scan_message":            scanMsg,
		"scan_status":             status,
		"masked":                  "false",
		"type":                    util.ComplianceScanLogsIndexName,
		"node_name":               config.NodeId,
		"node_id":                 config.NodeId,
		"kubernetes_cluster_name": config.NodeId,
		"kubernetes_cluster_id":   config.NodeId,
		"compliance_check_type":   scanType,
	}
	for k, v := range extras {
		scanLog[k] = v
	}
	scanLogJson, err := json.Marshal(scanLog)
	if err != nil {
		logrus.Error("Error parsing JSON: ", scanLog)
		return err
	}
	ingestScanStatusAPI := fmt.Sprintf("https://" + config.ManagementConsoleUrl + "/df-api/ingest?doc_type=" + util.ComplianceScanLogsIndexName)
	_, _, err = util.HttpRequest(MethodPost, ingestScanStatusAPI, string(scanLogJson), nil, config)
	return err
}

func IngestComplianceResults(complianceDocs []util.ComplianceDoc, config util.Config) error {
	logrus.Debugf("Number of docs to ingest: %d", len(complianceDocs))
	docBytes, err := json.Marshal(complianceDocs)
	if err != nil {
		logrus.Error(err)
		return err
	}
	ingestScanStatusAPI := fmt.Sprintf("https://" + config.ManagementConsoleUrl + "/df-api/ingest?doc_type=" + util.ComplianceScanIndexName)
	_, _, err = util.HttpRequest("POST", ingestScanStatusAPI, string(docBytes), nil, config)
	return err
}
