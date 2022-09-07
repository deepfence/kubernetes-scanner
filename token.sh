token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
sed -i "s/-replaceToken-/$token/g" /home/deepfence/.kube/config