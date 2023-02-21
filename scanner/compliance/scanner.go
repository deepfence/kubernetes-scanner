package compliance

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/deepfence/kubernetes-scanner/util"
	"github.com/sirupsen/logrus"
)

type ComplianceScanner struct {
	config util.Config
}

func NewComplianceScanner(config util.Config) (*ComplianceScanner, error) {
	if config.ComplianceCheckType != util.NsaCisaCheckType {
		return nil, errors.New(fmt.Sprintf("invalid scan_type %s", config.ComplianceCheckType))
	}
	if config.ScanId == "" {
		return nil, errors.New("scan_id is empty")
	}
	return &ComplianceScanner{config: config}, nil
}

func (c *ComplianceScanner) RunComplianceScan() error {
	err := c.PublishScanStatus("", "INPROGRESS", nil)
	if err != nil {
		return err
	}
	tempFileName := fmt.Sprintf("/tmp/%s.json", util.RandomString(12))
	//defer os.Remove(tempFileName)
	spKubePath := "/opt/steampipe/steampipe-mod-kubernetes-compliance"
	cmd := fmt.Sprintf("cd %s && steampipe check --progress=false --output=none --export=%s benchmark.nsa_cisa_v1", spKubePath, tempFileName)
	stdOut, stdErr := exec.Command("bash", "-c", cmd).CombinedOutput()
	var complianceResults util.ComplianceGroup
	if _, err := os.Stat(tempFileName); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s: %v", stdOut, stdErr)
	}
	tempFile, err := os.Open(tempFileName)
	if err != nil {
		return err
	}
	results, err := io.ReadAll(tempFile)
	if err != nil {
		return err
	}
	err = json.Unmarshal(results, &complianceResults)
	if err != nil {
		return err
	}
	complianceDocs, complianceSummary, err := c.ParseComplianceResults(complianceResults)
	if err != nil {
		return err
	}
	err = c.IngestComplianceResults(complianceDocs)
	if err != nil {
		logrus.Error(err)
	}
	extras := map[string]interface{}{
		"node_name":    c.config.NodeName,
		"node_id":      c.config.NodeId,
		"result":       complianceSummary,
		"total_checks": complianceSummary.Alarm + complianceSummary.Ok + complianceSummary.Info + complianceSummary.Skip + complianceSummary.Error,
	}
	err = c.PublishScanStatus("", "COMPLETED", extras)
	if err != nil {
		logrus.Error(err)
	}
	return nil
}

func (c *ComplianceScanner) PublishScanStatus(scanMsg string, status string, extras map[string]interface{}) error {
	scanMsg = strings.Replace(scanMsg, "\n", " ", -1)
	scanLog := map[string]interface{}{
		"scan_id":                 c.config.ScanId,
		"time_stamp":              util.GetIntTimestamp(),
		"@timestamp":              util.GetDatetimeNow(),
		"scan_message":            scanMsg,
		"scan_status":             status,
		"type":                    util.ComplianceScanLogs,
		"node_name":               c.config.NodeName,
		"node_id":                 c.config.NodeId,
		"kubernetes_cluster_name": c.config.NodeName,
		"kubernetes_cluster_id":   c.config.NodeId,
		"compliance_check_type":   c.config.ComplianceCheckType,
	}
	for k, v := range extras {
		scanLog[k] = v
	}
	err := os.MkdirAll(filepath.Dir(c.config.ComplianceStatusFilePath), 0755)
	f, err := os.OpenFile(c.config.ComplianceResultsFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	byteJson, err := json.Marshal(scanLog)
	if err != nil {
		return err
	}
	if _, err = f.WriteString(string(byteJson) + "\n"); err != nil {
		logrus.Errorf("%+v \n", err)
	}
	return err
}

func (c *ComplianceScanner) IngestComplianceResults(complianceDocs []util.ComplianceDoc) error {
	logrus.Debugf("Number of docs to ingest: %d", len(complianceDocs))
	data := make([]map[string]interface{}, len(complianceDocs))
	for index, complianceDoc := range complianceDocs {
		mapData, err := util.StructToMap(complianceDoc)
		if err == nil {
			data[index] = mapData
		} else {
			logrus.Error(err)
		}
	}
	err := os.MkdirAll(filepath.Dir(c.config.ComplianceResultsFilePath), 0755)
	f, err := os.OpenFile(c.config.ComplianceResultsFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, d := range data {
		byteJson, err := json.Marshal(d)
		if err != nil {
			logrus.Errorf("%+v \n", err)
			continue
		}
		strJson := string(byteJson)
		strJson = strings.Replace(strJson, "\n", " ", -1)
		if _, err = f.WriteString(strJson + "\n"); err != nil {
			logrus.Errorf("%+v \n", err)
		}
	}
	return nil
}
