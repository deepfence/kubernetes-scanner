package main

import (
	"flag"
	"os"
	"path"
	"runtime"
	"strconv"

	"github.com/deepfence/kubernetes-scanner/scanner/compliance"
	"github.com/deepfence/kubernetes-scanner/util"
	"github.com/sirupsen/logrus"
)

var (
	managementConsoleUrl  = flag.String("mgmt-console-url", "", "Deepfence Management Console URL")
	managementConsolePort = flag.Int("mgmt-console-port", 443, "Deepfence Management Console Port")
	clusterName           = flag.String("cluster-name", "", "Cluster Name")
	debug                 = flag.Bool("debug", false, "set log level to debug")
)

func main() {
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
	nodeId := util.GetKubernetesClusterId()
	if nodeId == "" {
		nodeId = *clusterName
	}
	config := util.Config{
		ManagementConsoleUrl:  *managementConsoleUrl,
		ManagementConsolePort: strconv.Itoa(*managementConsolePort),
		DeepfenceKey:          os.Getenv("DEEPFENCE_KEY"),
		NodeName:              *clusterName,
		NodeId:                nodeId,
	}

	complianceScanner, err := compliance.NewComplianceScanner(config, "", util.NsaCisaCheckType)
	if err != nil {
		logrus.Error(err.Error())
		return
	}
	err = complianceScanner.RunComplianceScan()
	if err != nil {
		logrus.Error(err.Error())
	}
	// read results from file
}
