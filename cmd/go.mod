module github.com/deepfence/kubernetes-scanner/cmd/v2

go 1.23.2

replace github.com/deepfence/kubernetes-scanner/v2 => ../

require (
	github.com/deepfence/kubernetes-scanner/v2 v2.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.3
)

require golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
