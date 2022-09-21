# Helm chart for Deepfence Kubernetes Scanner

### Install

```shell
helm repo add deepfence-k8s-scanner https://deepfence-helm-charts.s3.amazonaws.com/deepfence-k8s-scanner
```

```shell
helm show values deepfence-k8s-scanner/deepfence-k8s-scanner
helm show readme deepfence-k8s-scanner/deepfence-k8s-scanner
```

```shell
helm install deepfence-k8s-scanner deepfence-k8s-scanner/deepfence-k8s-scanner \
    --set managementConsoleUrl="40.40.40.40" \
    --set deepfenceKey="xxxxx" \
    --set clusterName="prod-cluster" \
    --namespace deepfence-k8s-scanner \
    --create-namespace
```
