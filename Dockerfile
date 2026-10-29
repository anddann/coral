# Use Maven image with JDK 17
FROM maven:3.9.9-eclipse-temurin-17

# Install Python 3.9 explicitly
RUN apt-get update && \
    apt-get install -y --no-install-recommends software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y --no-install-recommends python3.9 python3.9-distutils python3.9-venv curl && \
    curl -sS https://bootstrap.pypa.io/get-pip.py | python3.9 && \
    ln -s /usr/bin/python3.9 /usr/local/bin/python && \
    rm -rf /var/lib/apt/lists/*



WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .



## use custom CVEs, and delete the dummy cves from the original repo
RUN rm vulnerabilities/* && cp custom_cves/vul_edges_unique.csv vulnerabilities/vul_edges_unique.csv

# ENVIRONMENT
ENV MONGO_HOST=ubuntu-server
ENV SEMSERVER_HOST=ubuntu-server
ENV GRAPH_API_HOST=ubuntu-server
ENV WEAVER_HOST=ubuntu-server
ENV M2_REPO=/Users/adann/.m2/repository/
ENV WORKSPACE=/usr/src/app


ENTRYPOINT [ "python", "experiment-main-entry.py" ]