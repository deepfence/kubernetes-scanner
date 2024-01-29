package compliance

import (
	"crypto/md5"
	"fmt"
	"strings"

	"github.com/deepfence/kubernetes-scanner/v2/util"
)

func (c *ComplianceScanner) parseControlResult(complianceDocs *[]util.ComplianceDoc, complianceSummary *map[string]map[string]struct{}, group util.ComplianceGroup, control util.ComplianceControl, result util.ComplianceControlResult) {

	docId := fmt.Sprintf("%x", md5.Sum([]byte(c.config.ScanId+control.ControlID+
		result.Resource+result.Reason)))
	(*complianceSummary)[result.Status][docId] = struct{}{}
	prefix := "kubernetes"
	service := strings.TrimPrefix(control.Tags.Service, prefix)

	resource := result.Resource
	var podName string
	var podNamespace string
	for _, dimension := range result.Dimensions {
		switch dimension.Key {
		case "pod_name":
			podName = dimension.Value
		case "namespace":
			podNamespace = dimension.Value
		}
	}
	if podName != "" {
		resource = fmt.Sprintf("%s (Namespace: %s, ID: %s)", podName, podNamespace, result.Resource)
	}

	complianceDoc := util.ComplianceDoc{
		Timestamp:           util.GetDatetimeNow(),
		TestRationale:       result.Reason,
		Resource:            resource,
		Status:              result.Status,
		Group:               group.Title,
		TestCategory:        service,
		TestInfo:            control.Title,
		ComplianceCheckType: c.config.ComplianceCheckType,
		NodeId:              fmt.Sprintf("%x", md5.Sum([]byte(c.config.NodeId+c.config.ScanId+control.ControlID+result.Resource+result.Reason))),
		NodeType:            "kubernetes_cluster",
		ScanId:              c.config.ScanId,
		Masked:              false,
		Type:                util.ComplianceScan,
		TestNumber:          control.ControlID,
		TestDesc:            control.Description,
		TestSeverity:        control.Severity,
	}
	*complianceDocs = append(*complianceDocs, complianceDoc)
}

func (c *ComplianceScanner) parseGroup(complianceDocs *[]util.ComplianceDoc, complianceSummary *map[string]map[string]struct{}, group util.ComplianceGroup) {
	for _, control := range group.Controls {
		for _, result := range control.Results {
			c.parseControlResult(complianceDocs, complianceSummary, group, control, result)
		}
	}
	for _, childGroup := range group.Groups {
		c.parseGroup(complianceDocs, complianceSummary, childGroup)
	}
}

func (c *ComplianceScanner) ParseComplianceResults(complianceResults util.ComplianceGroup) ([]util.ComplianceDoc, util.ComplianceSummary, error) {
	var complianceDocs []util.ComplianceDoc
	complianceSummaryMap := map[string]map[string]struct{}{
		util.StatusAlarm: make(map[string]struct{}),
		util.StatusOk:    make(map[string]struct{}),
		util.StatusInfo:  make(map[string]struct{}),
		util.StatusSkip:  make(map[string]struct{}),
		util.StatusError: make(map[string]struct{}),
		"":               make(map[string]struct{}),
	}
	for _, group := range complianceResults.Groups {
		c.parseGroup(&complianceDocs, &complianceSummaryMap, group)
	}
	return complianceDocs, util.ComplianceSummary{
		Alarm: len(complianceSummaryMap[util.StatusAlarm]),
		Ok:    len(complianceSummaryMap[util.StatusOk]),
		Info:  len(complianceSummaryMap[util.StatusInfo]),
		Skip:  len(complianceSummaryMap[util.StatusSkip]),
		Error: len(complianceSummaryMap[util.StatusError]),
	}, nil
}
