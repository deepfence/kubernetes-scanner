FROM golang:1.18-bullseye AS build

WORKDIR /home/deepfence/src/kspm
COPY . .
RUN go build -o kspm .
RUN chmod 777 kspm
RUN cp /home/deepfence/src/kspm/kspm /home/deepfence/
RUN rm -r /home/deepfence/src/*

FROM debian:bullseye-slim
MAINTAINER Deepfence Inc
LABEL deepfence.role=system

RUN apt-get update \
    && apt-get install -y bash curl wget git \
    && /bin/sh -c "$(curl -fsSL https://raw.githubusercontent.com/turbot/steampipe/main/install.sh)"

RUN useradd -rm -d /home/deepfence -s /bin/bash -g root -G sudo -u 1001 deepfence
USER deepfence

COPY --from=build /home/deepfence/kspm /usr/local/bin/kspm
WORKDIR /opt/steampipe
USER root
RUN chown deepfence /opt/steampipe
RUN chown deepfence /usr/local/bin/kspm
COPY kubeconfig /home/deepfence/.kube/config
COPY token.sh /home/deepfence/token.sh
RUN chown deepfence /home/deepfence/.kube/config 
RUN chown deepfence /home/deepfence/token.sh

USER deepfence
RUN steampipe plugin install steampipe \
    && steampipe plugin install kubernetes \
    && git clone https://github.com/turbot/steampipe-mod-kubernetes-compliance.git

#COPY kubeconfig /home/deepfence/.kube/config
#COPY token.sh /home/deepfence/token.sh
#RUN chown deepfence /home/deepfence/.kube/config
#RUN chown deepfence /home/deepfence/token.sh
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/kspm"]
