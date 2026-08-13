# ESPHome mmWave Radar Configs

> Production ESPHome configurations for HLK-LD2450, HLK-LD2451, and DFRobot C4001/SEN0609 mmWave radar sensors — integrating binary-protocol sensors with Home Assistant via MQTT-free direct API.

[![Platform](https://img.shields.io/badge/platform-ESP32-2ea043?style=flat-square)](.)
[![Framework](https://img.shields.io/badge/framework-ESPHome-1f6feb?style=flat-square)](.)
[![HA](https://img.shields.io/badge/integration-Home%20Assistant-41bdf5?style=flat-square)](.)

---

## What This Demonstrates

Building these configs required going below the ESPHome abstraction layer — parsing raw binary serial frames in C++ lambdas, implementing stateful protocol engines, and designing sensor pipelines that publish clean data to Home Assistant. These are the same skills that show up in log parser development, protocol analysis, and IoT security work.

**Skills demonstrated:**

| Skill | How |
|-------|-----|
| Embedded systems / firmware | ESPHome YAML + C++ lambdas running on ESP32 microcontrollers |
| Binary protocol parsing | Frame-level parsing of HLK-LD2450/LD2451 UART protocols (custom byte-level state machine in C++) |
| Serial communication | UART configuration, baud rate, buffer sizing, rx/tx pin assignment |
| IoT security practices | All credentials via `!secret` references — API keys, OTA passwords, fallback passwords never hardcoded |
| Home Assistant integration | Native API encryption, entity categorization, diagnostic vs. config vs. measurement state classes |
| Sensor data pipelines | Multi-target position tracking (x/y/speed/angle/SNR) published as individual HA entities |
| Systems debugging | Watchdog timers, frame validation, first-frame logging, NAN handling for absent targets |

---

## Sensors Covered

| Config | Sensor | Protocol | Targets | Key Features |
|--------|--------|----------|---------|--------------|
| [`ld2450-radar.yaml`](ld2450-radar.yaml) | HLK-LD2450 | Native ESPHome component | 3 simultaneous | Zone-based detection, multi-target x/y/speed/angle/resolution, Bluetooth config |
| [`ld2451-radar.yaml`](ld2451-radar.yaml) | HLK-LD2451 | Custom binary UART (256000 baud) | 3 simultaneous | Approaching/receding classification, SNR per target, alarm output, IR LED heartbeat |
| [`c4001-radar.yaml`](c4001-radar.yaml) | DFRobot C4001 / SEN0609 | ASCII command/response (9600 baud) | 1 primary + energy | Presence + distance-and-speed modes, configurable range/sensitivity/latency, micro-motion detection |

---

## How It Works

### LD2450 — Native Component

The LD2450 has a first-party ESPHome component. Configuration is declarative — define zones, enable multi-target tracking, expose entities:

```yaml
ld2450:
  id: ld2450_radar
  uart_id: uart_ld2450

sensor:
  - platform: ld2450
    target_1:
      x:
        name: Target-1 X
      y:
        name: Target-1 Y
      speed:
        name: Target-1 Speed
```

### LD2451 — Custom Binary Protocol

The LD2451 has no ESPHome component. The config implements a full protocol engine in C++ lambdas: frame synchronization, length validation, footer verification, command/data frame dispatch, and a watchdog timer that clears stale target state.

```
Frame structure (data):
  F4 F3 F2 F1  ← header
  [len 2B]     ← payload length
  [count 1B]   ← target count
  [alarm 1B]   ← alarm byte
  [targets...]  ← 5 bytes each: angle, distance, direction, speed, SNR
  F8 F7 F6 F5  ← footer

Frame structure (config ACK):
  FD FC FB FA  ← header
  [len 2B]
  [cmd 2B]
  [status 2B]
  [payload...]
  04 03 02 01  ← footer
```

Configuration commands (enable config mode → write → end config mode) are issued at boot and in response to HA number/select entity changes.

### C4001 — ASCII Command Protocol

The C4001 uses a human-readable command/response protocol at 9600 baud. Commands like `setRange 0.6 12.0`, `setSensitivity 7 5`, `setLatency 0 15` configure the sensor; responses are parsed from `Response <values>` lines. Presence data arrives as NMEA-style `$DFHPD` and `$DFDMD` sentences.

---

## Security — Secrets Management

All credentials use ESPHome's `!secret` mechanism. **No passwords or keys appear in these YAML files.**

```yaml
api:
  encryption:
    key: !secret api_key_ld2450   # ← references secrets.yaml (gitignored)

ota:
  - platform: esphome
    password: !secret ota_password_ld2450

wifi:
  ssid: !secret wifi_ssid
  password: !secret wifi_password
  ap:
    password: !secret fallback_password_ld2450
```

Copy [`secrets.yaml.example`](secrets.yaml.example) to `secrets.yaml` (gitignored), fill in your values, and generate fresh keys with:

```bash
python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

---

## Setup

1. Install [ESPHome](https://esphome.io/guides/installing_esphome.html)
2. Copy `secrets.yaml.example` → `secrets.yaml` and fill in your values
3. Flash to your ESP32:

```bash
esphome run ld2450-radar.yaml      # compile, flash, and open logs
esphome run ld2451-radar.yaml
esphome run c4001-radar.yaml
```

Home Assistant will auto-discover each device via the native API once it's on the network.

---

## Relevance to Security / Network Operations

| Home Lab Skill | Enterprise / SOC Equivalent |
|----------------|------------------------------|
| Binary protocol parsing (LD2451 UART frames) | Log parser / connector development (Logstash, Cribl, custom SIEM connector) |
| Secrets management with `!secret` references | Secrets management in production (Vault, AWS Secrets Manager, environment variables) |
| Sensor → entity → automation pipeline | Log source → SIEM ingest → alert rule |
| Watchdog timer clearing stale state | Timeout logic in correlation rules, alert expiry in SOAR platforms |
| OTA firmware updates | Remote endpoint management, patch deployment |
| API encryption with rotating keys | mTLS, API key rotation, encrypted agent communication |

---

## What I Learned

- **Protocol documentation is rarely complete.** The LD2451 has no ESPHome component and minimal English documentation. Getting it working required capturing live UART traffic with a logic analyzer, mapping the byte structure manually, and testing corner cases (zero targets, alarm byte, config ACK timing). This is the same process as reverse-engineering a proprietary log format.
- **State machines matter at the byte level.** The ring buffer + frame synchronization logic in the LD2451 config handles partial frames, corrupt headers, and buffer overflow gracefully — none of which the naive approach handles.
- **IoT credential hygiene is not default.** The original configs had API keys, OTA passwords, and fallback hotspot passwords hardcoded. Moving everything to `!secret` references is a small change with a large security impact — and directly analogous to the work of removing hardcoded credentials from application code.
