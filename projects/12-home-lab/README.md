# 🏠 Home Security Monitoring Lab

> A self-hosted physical security and monitoring infrastructure built on real hardware — integrating IoT sensors, AI-assisted NVR, MQTT messaging, and DNS-level security.

![Stack](https://img.shields.io/badge/stack-Home%20Assistant%20%2B%20ESPHome%20%2B%20Frigate-1f6feb?style=flat-square)
![Hardware](https://img.shields.io/badge/hardware-Raspberry%20Pi%204%20%2B%20ESP32-2ea043?style=flat-square)
![Type](https://img.shields.io/badge/type-Network%20Operations%20Lab-8957e5?style=flat-square)

---

## 🎯 Overview

This project demonstrates real network operations experience: sensor integration, protocol fluency (MQTT, HTTP, mDNS), layered monitoring, alerting pipelines, and DNS-level security — all running on physical hardware in a production home environment.

The skills here map directly to NOC/SOC environments: you can't monitor what you can't measure, and building the full pipeline from sensor → MQTT → automation → alert develops intuition for every layer of an operational monitoring stack.

---

## 🧰 Skills & Technologies

**Platforms & Infrastructure**
- Home Assistant OS on Raspberry Pi 4 — orchestration, automation, dashboards
- ESPHome — firmware for ESP32 microcontrollers (sensor → MQTT bridge)
- Frigate NVR — self-hosted AI object detection video recording

**Protocols & Networking**
- MQTT (Mosquitto broker) — lightweight pub/sub messaging for IoT sensors
- HTTP/REST — Home Assistant API, Frigate API
- mDNS — local service discovery
- DNS — AdGuard Home for DNS-level ad/malware blocking

**Sensors & Hardware**
- mmWave radar: HLK-LD2450 (multi-target tracking), HLK-LD2451, DFRobot C4001/SEN0609
- ESP32 microcontrollers with ESPHome firmware
- ESP32-CAM with MJPEG2SD firmware
- IP cameras integrated with Frigate NVR

**Security Controls**
- DNS-level blocking (AdGuard Home) — blocks known malicious/tracking domains at the resolver
- Network segmentation — IoT devices isolated from primary LAN
- DHCP workaround — AdGuard integrated despite ISP gateway's locked DHCP

---

## 🏗️ Architecture

```
[Physical Layer]
mmWave Radars ──► ESP32 (ESPHome)
IP Cameras    ──► Frigate NVR (AI object detection)
                         │                │
                    MQTT messages    HTTP events
                         │                │
                         ▼                ▼
                  [Mosquitto MQTT Broker]
                         │
                         ▼
              [Home Assistant OS — Raspberry Pi 4]
              ┌─────────────────────────────────┐
              │  Automations (YAML)             │
              │  Lovelace Dashboards            │
              │  Notification pipeline          │
              │  AdGuard Home (DNS sinkhole)    │
              └─────────────────────────────────┘
                         │
                  Mobile push alerts
                  (notify.mobile_app)
```

---

## 🔬 Technical Deep-Dives

### mmWave Radar Sensors

The HLK-LD2450 and DFRobot C4001 sensors use 24GHz FMCW radar to detect and track multiple targets simultaneously — including position, speed, and distance vectors. Unlike PIR (passive infrared) sensors, mmWave works through non-metallic walls and isn't fooled by slow movement.

ESPHome firmware handles the serial parsing protocol and publishes parsed data to MQTT topics:

```yaml
# esphome-configs/ld2450.yaml (excerpt)
sensor:
  - platform: ld2450
    baud_rate: 256000
    target_1:
      x:
        name: "Target 1 X"
      y:
        name: "Target 1 Y"
      speed:
        name: "Target 1 Speed"
```

The radar data feeds into custom Lovelace dashboards that render real-time radar visualization cards — live position tracking in the browser.

### MQTT Pipeline

Every sensor publishes to a structured topic hierarchy:

```
homelab/sensors/radar/living_room/target1/x     → 1.2
homelab/sensors/radar/living_room/target1/y     → 0.8
homelab/sensors/radar/living_room/target1/speed → -0.3
homelab/cameras/front_door/person_detected      → 1
```

Home Assistant subscribes to these topics and triggers automations based on state changes.

### Frigate NVR + AI Object Detection

Frigate uses ffmpeg for capture and a Coral TPU (or CPU inference) to run object detection on every camera frame:

- Detects: person, car, bicycle, animal
- Stores motion-triggered clips only (not continuous recording)
- Exposes detected objects via MQTT and HTTP API
- Integrates with Home Assistant for trigger automations on person detection

### AdGuard Home — DNS-Level Security

DNS-level blocking intercepts queries for known malicious/tracking domains before any TCP connection is established:

- Blocks ad networks, tracking pixels, known malware C2 domains
- Query logs provide visibility into every DNS request on the network — useful for detecting suspicious lookups from IoT devices
- Deployed workaround for ISP gateway's locked DHCP (forced via static DNS on individual devices + HA integration)

```bash
# Typical blocked query log entry
2025-xx-xx 02:31:44  BLOCKED  malware-domain.xyz  192.168.x.x → AdGuard (local)
```

### Alerting Pipeline

```
Frigate detects person on camera
    → MQTT publish: frigate/front_door/person → 1
    → HA automation triggers
    → notify.mobile_app_sms fires
    → push notification delivered with camera snapshot
```

---

## 🛡️ Security Relevance to SOC/NOC Work

| Home Lab Skill | Enterprise Equivalent |
|-|-|
| MQTT subscriber/publisher, topic design | Message bus / event stream architecture (Kafka, Azure Event Hub) |
| Sensor → MQTT → automation pipeline | Log source → SIEM ingestion → alert rule |
| AdGuard DNS logging + blocking | Corporate DNS firewall (Cisco Umbrella, Palo Alto DNS Security) |
| Frigate NVR + alert automation | Physical security integration (PSIM, camera-to-SIEM integration) |
| ESPHome serial protocol parsing | Log parser / connector development (Logstash, Cribl) |
| DHCP/DNS architecture workaround | Network troubleshooting, understanding resolver chain |

---

## 📁 Contents

```
esphome-configs/
├── ld2450-radar.yaml       ← HLK-LD2450 mmWave radar config
├── ld2451-radar.yaml       ← HLK-LD2451 variant
├── c4001-radar.yaml        ← DFRobot C4001/SEN0609 config
└── esp32cam.yaml           ← ESP32-CAM / MJPEG2SD integration

automations/
├── person_alert.yaml       ← Frigate person detection → push notify
├── radar_presence.yaml     ← mmWave presence → lighting automation
└── adguard_stats.yaml      ← Daily DNS stats notification

lovelace/
├── radar_dashboard.yaml    ← Real-time mmWave radar visualization card
└── security_overview.yaml  ← Consolidated sensor + camera status view
```

---

## 📚 What I Learned

- **MQTT is everywhere in IoT and industrial monitoring.** Understanding publish/subscribe patterns, topic hierarchy design, and QoS levels translates directly to message bus architectures used in enterprise security pipelines.
- **DNS visibility is underrated.** AdGuard's query logs give me visibility into every DNS lookup on the network — it's the same principle behind enterprise DNS security platforms. Anomalous DNS (unusual TLDs, DGA-like patterns, unexpected external queries from IoT devices) is a high-signal indicator.
- **Sensor integration requires protocol knowledge.** Reading the HLK-LD2450 serial protocol, parsing binary frames, and mapping them to Home Assistant entities requires understanding of byte-level protocol parsing — the same skill used in writing log parsers for security tooling.
- **Alerting systems need tuning.** My first person-detection alert fired constantly on car headlights. The tuning process — adjusting detection zones, confidence thresholds, time-of-day filtering — is directly analogous to tuning SIEM rules to reduce false positives.
