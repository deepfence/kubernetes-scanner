module github.com/deepfence/kubernetes-scanner/cmd

go 1.20

replace github.com/deepfence/kubernetes-scanner => ../

require (
	github.com/deepfence/kubernetes-scanner v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.3
)

require golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
