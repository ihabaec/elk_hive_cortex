# 🛡️ SOC Platform: Elasticsearch + Kibana + TheHive + Cortex + MISP + OpenCTI

[![Build Status](https://img.shields.io/badge/Status-Stable-brightgreen?style=flat&logo=docker)](https://github.com/ihabaec/elk_hive_cortex)
[![Elastic Stack](https://img.shields.io/badge/Elastic%20Stack-9.0.3-00bfb3?style=flat&logo=elastic)](https://www.elastic.co/elastic-stack/)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-blue?style=flat&logo=docker)](https://docs.docker.com/compose/)

Run a **complete SOC & Threat Intelligence platform** with Docker and Docker Compose.

This setup provides an end-to-end **Security Operations Center (SOC) pipeline**:
- **Elasticsearch & Kibana** → log ingestion, indexing, dashboards, detection rules.  
- **TheHive** → incident & case management.  
- **Cortex** → automated analyzers and responders.  
- **MISP** → Threat Intelligence feeds & correlation.  
- **OpenCTI** → advanced CTI, campaign tracking, MITRE ATT&CK mapping.  

---

## 📖 Philosophy

The goal of this project is to provide the **simplest possible entry point** into building a modern, open-source SOC.  
Instead of focusing only on detection (SIEM), this stack goes further by integrating **incident response and CTI enrichment**.

**Design principles:**
- **Portability**: Everything runs inside Docker containers.  
- **Automation**: Single script (`./start.sh`) to start all services.  
- **Extensibility**: Add analyzers, responders, or feeds without breaking the base setup.  
- **Realism**: Simulates how a SOC works in production (alerts → cases → enrichment → intelligence).  

---

## 🖥️ Requirements

### Host setup
* [Docker Engine](https://docs.docker.com/get-started/get-docker/) v20.10+  
* [Docker Compose](https://docs.docker.com/compose/install/) v2.0+  
* [Git](https://git-scm.com/)  

**Hardware requirements:**
- 20 GB RAM virtual machine or equivalent hardware
- 50 GB disk space  

### Ports
| Service       | Port  | URL |
|---------------|-------|-----|
| Elasticsearch | 9200  | <http://localhost:9200> |
| Kibana        | 5601  | <http://localhost:5601> |
| TheHive       | 9000  | <http://localhost:9000> |
| Cortex        | 9001  | <http://localhost:9001> |
| MISP          | 80  | <http://localhost> |
| OpenCTI       | 8080  | <http://localhost:8080> |

---

## 🚀 Usage

### Cloning the repository

```sh
git clone https://github.com/ihabaec/elk_hive_cortex.git
cd elk_hive_cortex
```

### Bringing up the stack

Start all services with a single command:

```sh
./start.sh
```

> ⏳ Wait a few minutes for all containers to initialize (especially Elasticsearch, MISP, and OpenCTI).

### Initial setup

1. **Kibana**

   * Create index patterns (`winlogbeat-*`).
   * Import and enable detection rules.

2. **TheHive**

   * Create an admin user, organizations, and API keys.
   * Enable connectors to Cortex and MISP.

3. **Cortex**

   * Install analyzers and responders (`VirusTotal`, `AbuseIPDB`, `URLhaus`, custom responders).
   * Configure API keys.

4. **MISP**

   * Configure admin account.
   * Add OSINT feeds and enable taxonomies/galaxies.

5. **OpenCTI**

   * Generate an API key.
   * Connect to TheHive and OpenCTI using the connecter image.

### Cleanup

To stop all services:

```sh
CTRL-C
```

To stop and remove **all data**:

```sh
docker compose down -v
```

---

## ⚙️ Configuration

### How to configure Elasticsearch

Edit [`elasticsearch/config/elasticsearch.yml`](./elasticsearch/config/elasticsearch.yml).
Override options via environment variables in `docker-compose.yml`.

### How to configure Kibana

Edit [`kibana/config/kibana.yml`](./kibana/config/kibana.yml).
Used for dashboards, SIEM rules, and alerts.

### How to configure TheHive

* Access via [http://localhost:9000](http://localhost:9000).
* Add API keys for automation.
* Run the python thehive-elastic.py to import cases/alerts from kibana alerts.

### How to configure Cortex

* Access via [http://localhost:9001](http://localhost:9001).
* Install analyzers and responders (NOTE: for each new analyzer/responder you will have to install the dependancies on the image).
* Update `application.conf` with correct keys.

### How to configure MISP

* Access via [http://localhost](http://localhost).
* Set up feeds, users, taxonomies.
* Connect to TheHive for automatic case export.

### How to configure OpenCTI

* Access via [http://localhost:8080](http://localhost:8080).
* Create API keys.

---

## 📜 License

This project is open-source for academic and professional use.
Components are licensed under their respective upstream projects:

* Elasticsearch & Kibana → Elastic License
* TheHive & Cortex → AGPL v3
* MISP → GPL v3
* OpenCTI → Apache 2.0
