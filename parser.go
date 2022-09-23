package main

import (
	"crypto/md5"
	"fmt"
	"github.com/deepfence/kspm/util"
	"strings"
)

func parseControlResult(complianceDocs *[]util.ComplianceDoc, complianceSummary *map[string]map[string]struct{}, group util.ComplianceGroup, control util.ComplianceControl, result util.ComplianceControlResult, config util.Config) {

	docId := fmt.Sprintf("%x", md5.Sum([]byte(config.ScanId+control.ControlID+
		result.Resource+result.Reason)))
	(*complianceSummary)[result.Status][docId] = struct{}{}
	prefix := "kubernetes"
	service := strings.TrimPrefix(control.Tags.Service, prefix)

	complianceDoc := util.ComplianceDoc{
		Timestamp: util.GetDatetimeNow(),
		// Count:               1,
		TestRationale:         result.Reason,
		Resource:              result.Resource,
		Status:                result.Status,
		Group:                 group.Title,
		TestCategory:          service,
		TestInfo:              control.Title,
		ComplianceCheckType:   "nsa-cisa",
		NodeType:              "kubernetes",
		NodeName:              config.NodeName,
		NodeId:                config.NodeId,
		KubernetesClusterName: config.NodeName,
		KubernetesClusterId:   config.NodeId,
		ScanId:                config.ScanId,
		Masked:                "false",
		Type:                  util.ComplianceScanIndexName,
		TestNumber:            control.ControlID,
		TestDesc:              control.Description,
		TestSeverity:          control.Severity,
	}
	*complianceDocs = append(*complianceDocs, complianceDoc)
}

func parseGroup(complianceDocs *[]util.ComplianceDoc, complianceSummary *map[string]map[string]struct{}, group util.ComplianceGroup, config util.Config) {
	for _, control := range group.Controls {
		for _, result := range control.Results {
			parseControlResult(complianceDocs, complianceSummary, group, control, result, config)
		}
	}
	for _, childGroup := range group.Groups {
		parseGroup(complianceDocs, complianceSummary, childGroup, config)
	}
}

func ParseComplianceResults(complianceResults util.ComplianceGroup, config util.Config) ([]util.ComplianceDoc, util.ComplianceSummary, error) {
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
		parseGroup(&complianceDocs, &complianceSummaryMap, group, config)
	}
	return complianceDocs, util.ComplianceSummary{
		Alarm: len(complianceSummaryMap[util.StatusAlarm]),
		Ok:    len(complianceSummaryMap[util.StatusOk]),
		Info:  len(complianceSummaryMap[util.StatusInfo]),
		Skip:  len(complianceSummaryMap[util.StatusSkip]),
		Error: len(complianceSummaryMap[util.StatusError]),
	}, nil
}
