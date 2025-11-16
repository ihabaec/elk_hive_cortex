# Security Operations Platform - ELK + TheHive + Cortex

A comprehensive security operations and threat intelligence platform integrating the Elastic Stack (ELK), TheHive, Cortex, MISP, and OpenCTI for advanced SIEM capabilities and incident response.

[![Elastic Stack version](https://img.shields.io/badge/Elastic%20Stack-7.17.13-00bfb3?style=flat&logo=elastic-stack)](https://www.elastic.co/blog/category/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [Components](#components)
- [Integration Details](#integration-details)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

## Overview

This project provides a complete security operations platform that combines:

- **Elastic Stack (ELK)**: Log aggregation, search, and visualization
- **TheHive**: Security incident response platform
- **Cortex**: Observable analysis and active response engine
- **MISP**: Threat intelligence platform for sharing, storing and correlating IoCs
- **OpenCTI**: Open Cyber Threat Intelligence platform
- **Custom Integration**: Automated alert forwarding from Elasticsearch to TheHive

The platform enables security teams to:
- Collect and analyze security logs in real-time
- Automatically create security incidents from SIEM alerts
- Enrich observables with threat intelligence
- Orchestrate incident response workflows
- Share and consume threat intelligence

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Operations Platform              │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │Logstash  │───▶│Elastic-  │───▶│ Kibana   │              │
│  │          │    │search    │    │          │              │
│  └──────────┘    └────┬─────┘    └──────────┘              │
│                       │                                       │
│                       │ elastic-thehive.py                   │
│                       ▼                                       │
│                  ┌──────────┐                                │
│                  │ TheHive  │                                │
│                  └────┬─────┘                                │
│                       │                                       │
│                       ├──────▶┌──────────┐                  │
│                       │       │  Cortex  │                  │
│                       │       └──────────┘                  │
│                       │                                       │
│                       ├──────▶┌──────────┐                  │
│                       │       │   MISP   │                  │
│                       │       └──────────┘                  │
│                       │                                       │
│                       └──────▶┌──────────┐                  │
│                               │ OpenCTI  │                  │
│                               └──────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

## Features

### SIEM Capabilities
- Real-time log collection and analysis
- Advanced search and filtering with Elasticsearch
- Custom detection rules and alerts
- Interactive dashboards and visualizations with Kibana

### Incident Response
- Automated alert-to-case creation
- Observable extraction and enrichment
- Case templates for common incident types
- Investigation task automation
- Collaborative case management

### Threat Intelligence
- IoC sharing and correlation with MISP
- Threat actor tracking with OpenCTI
- Automated observable analysis with Cortex
- Integration with multiple threat intelligence feeds

### Automation
- Automatic alert ingestion from Elasticsearch to TheHive
- Hash extraction from process execution events
- Observable deduplication
- Task creation based on alert severity
- Support for ECS (Elastic Common Schema) format

## Prerequisites

### System Requirements
- **OS**: Linux, macOS, or Windows with WSL2
- **RAM**: Minimum 8GB (16GB recommended)
- **Disk**: 50GB+ free space
- **CPU**: 4+ cores recommended

### Software Requirements
- [Docker Engine](https://docs.docker.com/get-started/get-docker/) version 18.06.0 or newer
- [Docker Compose](https://docs.docker.com/compose/install/) version 2.0.0 or newer
- Python 3.7+ (for the integration script)

### Network Ports

The stack exposes the following ports:

| Port | Service | Description |
|------|---------|-------------|
| 5044 | Logstash | Beats input |
| 5601 | Kibana | Web UI |
| 9000 | TheHive | Web UI |
| 9001 | Cortex | Web UI |
| 9200 | Elasticsearch | HTTP API |
| 9300 | Elasticsearch | Transport |
| 9600 | Logstash | Monitoring API |
| 50000 | Logstash | TCP/UDP input |
| 8080 | MISP | Web UI (if enabled) |

## Quick Start

### 1. Clone the Repository

```bash
git clone <repository-url>
cd docker-elk
```

### 2. Configure Environment Variables

Copy the example environment file and customize it:

```bash
cp .env.example .env
```

Edit [.env](.env) and update the following critical settings:

```bash
# Elasticsearch credentials
ELASTIC_PASSWORD=your_secure_password_here

# TheHive API key (generate after first setup)
THEHIVE_API_KEY=your_thehive_api_key

# MISP settings (if using)
ADMIN_PASSWORD=your_misp_admin_password
MYSQL_PASSWORD=your_mysql_password
```

### 3. Initialize the Stack

Run the setup container to initialize Elasticsearch users:

```bash
docker compose up setup
```

Wait for the setup to complete successfully.

### 4. Start All Services

#### Option A: Use the Start Script (Recommended)

```bash
chmod +x start.sh
./start.sh
```

This will start all services (ELK, TheHive, Cortex, MISP, OpenCTI) in the correct order.

#### Option B: Start Manually

```bash
# Start ELK Stack + TheHive + Cortex
docker compose up -d

# Start MISP (optional)
cd misp-docker && docker compose up -d && cd ..

# Start OpenCTI (optional)
cd opencti-docker && docker compose up -d && cd ..
```

### 5. Access the Services

Wait 2-3 minutes for all services to initialize, then access:

- **Kibana**: http://localhost:5601
  - Username: `elastic`
  - Password: (from `.env` file)

- **TheHive**: http://localhost:9000
  - Default credentials will be shown on first access

- **Cortex**: http://localhost:9001
  - Configure on first access

- **Elasticsearch**: http://localhost:9200

### 6. Start the Integration Script

Install Python dependencies:

```bash
pip install -r requirements.txt
# or manually:
pip install elasticsearch requests
```

Update the configuration in [elastic-thehive.py](elastic-thehive.py):

```python
# Elasticsearch Configuration
ES_AUTH = ("elastic", "your_password")

# TheHive Configuration
THEHIVE_API_KEY = "your_thehive_api_key"
```

Run the integration script:

```bash
python3 elastic-thehive.py
```

The script will continuously monitor Elasticsearch for SIEM alerts and automatically create cases in TheHive.

## Configuration

### Elasticsearch

Configuration file: [elasticsearch/config/elasticsearch.yml](elasticsearch/config/elasticsearch.yml)

Key settings can also be configured via environment variables in [docker-compose.yml](docker-compose.yml):

```yaml
elasticsearch:
  environment:
    ES_JAVA_OPTS: -Xms512m -Xmx512m  # Heap size
    discovery.type: single-node
```

### Logstash

Configuration file: [logstash/config/logstash.yml](logstash/config/logstash.yml)

Pipeline configuration: [logstash/pipeline/](logstash/pipeline/)

### Kibana

Configuration file: [kibana/config/kibana.yml](kibana/config/kibana.yml)

### TheHive

Configuration file: [thehive/application.conf](thehive/application.conf)

Key configuration points:
- Elasticsearch backend connection
- Authentication settings
- Cortex integration

### Cortex

Configuration file: [cortex/application.conf](cortex/application.conf)

Analyzers directory: [analyzers/](analyzers/)

### Integration Script

Edit [elastic-thehive.py](elastic-thehive.py) to configure:

```python
# Polling interval (seconds)
POLL_INTERVAL = 30

# Elasticsearch index to monitor
ES_INDEX = ".siem-signals-default"

# TheHive alert/case creation settings
```

## Usage

### Creating SIEM Detection Rules

1. Access Kibana at http://localhost:5601
2. Navigate to **Security** > **Rules**
3. Create detection rules for threats
4. Alerts will automatically flow to TheHive

### Working with TheHive Cases

1. Access TheHive at http://localhost:9000
2. View automatically created cases from Elasticsearch alerts
3. Cases include:
   - Alert metadata and description
   - Extracted observables (hashes, filenames, IPs, etc.)
   - Pre-created investigation tasks for high-severity incidents
   - Links back to original Elasticsearch alerts

### Analyzing Observables with Cortex

1. Install analyzers in the [analyzers/](analyzers/) directory
2. Configure Cortex connection in TheHive
3. Run analyzers on observables directly from TheHive cases
4. Results enrich your investigation with threat intelligence

### Using Case Templates

TheHive templates are available in [analyzers/thehive-templates/](analyzers/thehive-templates/)

Templates provide pre-configured:
- Custom fields for specific incident types
- Task checklists
- Metrics for tracking

## Components

### Elastic Stack

- **Elasticsearch 7.17.13**: Distributed search and analytics engine
- **Logstash 7.17.13**: Server-side data processing pipeline
- **Kibana 7.17.13**: Data visualization and exploration

### Security & Response

- **TheHive 5**: Security incident response platform
  - Case management
  - Observable tracking
  - Task automation

- **Cortex**: Observable analysis and active response
  - 100+ analyzers for enrichment
  - Responders for automated actions
  - Neuron job management

### Threat Intelligence (Optional)

- **MISP**: Malware Information Sharing Platform
- **OpenCTI**: Open Cyber Threat Intelligence Platform

## Integration Details

### Elasticsearch to TheHive Integration

The [elastic-thehive.py](elastic-thehive.py) script provides:

#### Features
- **Automated Alert Forwarding**: Monitors Elasticsearch SIEM signals index
- **Observable Extraction**: Extracts IoCs from ECS-formatted events:
  - Process names and paths
  - File hashes (MD5, SHA1, SHA256, SHA512, SSDEEP, Imphash)
  - Event IDs
  - Network indicators (when present)

- **Case Creation**: Automatically creates TheHive cases with:
  - Descriptive titles based on detection rule
  - Full context from original events
  - Severity mapping
  - Investigation tasks (for high-severity alerts)

- **Deduplication**: Prevents duplicate observables
- **Template Support**: Uses case templates for specific threat types (e.g., Mimikatz)
- **Incremental Processing**: Tracks last processed alert to avoid duplicates

#### How It Works

1. Script polls Elasticsearch index `.siem-signals-default` every 30 seconds
2. For each new alert:
   - Fetches original event data for complete context
   - Extracts observables (hashes, filenames, etc.)
   - Creates an alert in TheHive
   - Creates a case with all observables
   - Adds investigation tasks for high-severity incidents
3. Tracks processed alerts in `.last_alert_id` file

## Troubleshooting

### Common Issues

#### Elasticsearch fails to start
```bash
# Check logs
docker compose logs elasticsearch

# Common fix: Increase vm.max_map_count
sudo sysctl -w vm.max_map_count=262144
```

#### TheHive cannot connect to Elasticsearch
- Verify Elasticsearch is running: `curl http://localhost:9200`
- Check TheHive configuration in [thehive/application.conf](thehive/application.conf)
- Ensure correct credentials are set

#### Integration script errors
```bash
# Enable debug logging
# Edit elastic-thehive.py and set:
logging.basicConfig(level=logging.DEBUG)

# Check Elasticsearch connectivity
curl -u elastic:password http://localhost:9200/.siem-signals-default/_search

# Verify TheHive API key
curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:9000/api/status
```

#### Memory issues
```bash
# Reduce Java heap sizes in docker-compose.yml
ES_JAVA_OPTS: -Xms256m -Xmx256m
LS_JAVA_OPTS: -Xms128m -Xmx128m
```

### Logs

View logs for specific services:

```bash
docker compose logs -f elasticsearch
docker compose logs -f logstash
docker compose logs -f kibana
docker compose logs -f thehive
docker compose logs -f cortex
```

## Security Considerations

### Authentication & Authorization

1. **Change Default Passwords**: Update all default passwords in `.env` before production use
2. **API Keys**: Generate strong API keys for TheHive and rotate regularly
3. **Network Isolation**: Use Docker networks to isolate services
4. **TLS/SSL**: Enable TLS for production deployments (see ELK Stack TLS documentation)

### Secrets Management

- Never commit `.env` file to version control
- Use Docker secrets or external secret management for production
- Rotate credentials regularly

### Production Hardening

- Enable Elasticsearch security features
- Configure firewall rules to restrict port access
- Use reverse proxy with authentication for web UIs
- Enable audit logging
- Regular backups of Elasticsearch indices and TheHive database

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project includes components with different licenses:

- This integration: Apache License 2.0 (see [LICENSE](LICENSE))
- Elastic Stack: Elastic License
- TheHive: AGPL-3.0
- Cortex: AGPL-3.0

Please review individual component licenses before use.

## References

- [Elastic Stack Documentation](https://www.elastic.co/guide/index.html)
- [TheHive Documentation](https://docs.strangebee.com/)
- [Cortex Documentation](https://github.com/TheHive-Project/Cortex)
- [MISP Documentation](https://www.misp-project.org/documentation/)
- [OpenCTI Documentation](https://docs.opencti.io/)

## Acknowledgments

Based on the excellent [docker-elk](https://github.com/deviantony/docker-elk) project by [@deviantony](https://github.com/deviantony), extended with security operations and threat intelligence capabilities.

---

**Note**: This platform is designed for security operations and threat intelligence purposes. Ensure compliance with your organization's security policies and applicable laws when deploying and using this system.
