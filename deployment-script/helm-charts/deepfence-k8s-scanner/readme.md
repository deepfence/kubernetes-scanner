# Helm chart for Deepfence Kubernetes Scanner

### Install

**Quick start**

```bash
helm repo add deepfence-k8s-scanner https://deepfence-helm-charts.s3.amazonaws.com/deepfence-k8s-scanner
```

```bash
helm install deepfence-k8s-scanner deepfence-k8s-scanner/deepfence-k8s-scanner \
    --set managementConsoleUrl=40.40.40.40 \
    --set deepfenceKey="" \
    --set clusterName="prod-cluster" \
    --namespace deepfence-k8s-scanner \
    --create-namespace
```
