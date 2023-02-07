module github.com/deepfence/kubernetes-scanner/cmd

go 1.19

replace github.com/deepfence/kubernetes-scanner => ../

require (
	github.com/deepfence/kubernetes-scanner v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.0
)

require golang.org/x/sys v0.4.0 // indirect
