# cortex/Dockerfile
FROM thehiveproject/cortex:3.1

USER root

# Remove problematic Amazon Corretto repository and install packages
RUN rm -f /etc/apt/sources.list.d/corretto.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    libmagic1 \
    libmagic-dev \
    file \
    gcc \
    libc6-dev \
    libffi-dev \
    python3-dev \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies globally
RUN pip3 install --no-cache-dir \
    cortexutils \
    future \
    requests \
    vt-py \
    python-magic \
    filetype

# Don't switch back to cortex user - let the base image handle it
# USER cortex