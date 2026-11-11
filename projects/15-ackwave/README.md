# ackwave: Motion Sensing from Wi-Fi ACKs, Without Joining the Network

> An ESP32-S3 that detects human motion from the radio channel to a Wi-Fi router it never connects to. It uses "Polite Wi-Fi": every 802.11 device acknowledges frames addressed to it, even from senders that are not on the network.

> **Scope:** Built and tested only against my own router and devices. The same technique works against any Wi-Fi device in radio range, which is the security point of this project. Do not point it at networks or devices you don't own.

**Code:** [github.com/skausky/ackwave](https://github.com/skausky/ackwave)

## Overview

Wi-Fi sensing usually needs a device that is joined to the network and generating traffic. ackwave does not join. It sends ~100 small frames per second to the router from a made-up sender address. The router's radio acknowledges each one before any authentication or encryption check, and the board reads the **Channel State Information (CSI)** of every ACK: per-subcarrier amplitude across 52 subcarriers. A person moving changes the multipath reflections, and the detector on the board turns that into motion / still.

No password, no association, no IP address: the router never lists the board as a client.

## Skills & Technologies

- **Embedded C** on ESP-IDF v5.3 / FreeRTOS: raw 802.11 frame injection, promiscuous-mode CSI capture, ACK matching
- **Signal processing**: band-pass filtering, short/long energy windows, auto-calibrated noise floor, hysteresis
- **802.11 internals**: frame types, ACK behaviour, beacons and BSSIDs, channel tracking
- **Python** (NumPy, matplotlib): live GUI, recorder, history viewer, offline replay of the C detector, Doppler and breathing-rate analysis
- **Web dashboard** (stdlib HTTP server, Server-Sent Events, canvas charts): localhost-only by design and reached from a phone over an SSH tunnel; commands need a custom header and a local Host, so other web pages can't drive the board (CSRF and DNS-rebinding defence)
- **Testing**: 300+ C unit checks plus Python pipeline and dashboard tests that check the firmware and the Python model agree on synthetic and recorded data

## How it works

```
ESP32-S3 (not associated)                   Router
   │  null-data frame, fake source MAC  ──▶  │
   │  ◀──  802.11 ACK (sent by the PHY,      │
   │        before any auth/crypto check)    │
   ▼
CSI of each ACK (52 subcarriers, ~97/s)
   ▼
glitch filter → band-pass → short (0.5 s) + long (4 s) energy
   ▼
score ÷ auto-calibrated quiet level → MOTION / STILL (on the board)
   ▼
USB serial → web dashboard / live GUI, recorder, history (optional; the board also works standalone)
```

## Results and lessons

- **Steady ~97 samples/s** from the router without being connected, independent of how busy the network is.
- **Validated overnight against a mmWave radar** (DFRobot C4002) placed next to the bed: ackwave caught the larger movements; small movements of a person lying still were only partly caught (17 of 59 radar events), which set the next goal.
- **Found and filtered a router artefact.** The gateway runs a background scan every 20 min 2 s: its ACKs stop for ~175 ms and come back with a different channel shape, which looked like motion. A gap-aware shape filter now ignores it (51 of 52 such events overnight), while real movement still passes.
- **Cut false alarms by measuring, not guessing.** Replaying the night against the radar showed the short (0.5 s) window alone added no detections but doubled false alarms. Gating it on the long window took false alarms from 17.3 to 7.1 per hour with no detections lost.
- **Breathing at close range.** Standing still about 1 m from the board on the board-router line, the breathing rate (10-11/min, counted) showed clearly; further away or off that line it did not.
- **More links is not automatically better.** When the board also started poking a distant second access point, the main link's sample rate halved (97 → 43/s). This matches published research on multi-link Wi-Fi sensing ("dilution effect", arXiv 2602.10823) and shaped the design of an experimental multi-device mode: per-link detectors and quality gating instead of naive fusion.

## Defender's view

| | |
|---|---|
| **What it exploits** | 802.11 devices ACK any frame addressed to them, before authentication or decryption. WPA2/WPA3 don't change this. |
| **What an attacker gets** | Presence and motion inside a building from outside it, without credentials, with ~$10 of hardware. Breathing rate is possible at close range (seen here at ~1 m; published research shows more with better hardware). |
| **Detection** | A wireless IDS can flag a steady, high-rate stream (~100/s) of null-data frames to an AP from a MAC address that never associates. Kismet-style monitoring would see it, and nothing on the wired side would. |
| **Mitigation** | Limited: the ACK is sent by the radio hardware within microseconds. Options are RF monitoring, physical placement, and vendor-level changes to the standard (sensing is being formalised in IEEE 802.11bf). |

## Credit

The Polite Wi-Fi behaviour was described by Ali Abedi and Omid Abari (University of Waterloo). ackwave is my own implementation on an ESP32-S3, with an on-device detector, calibration, glitch filtering and tooling.
