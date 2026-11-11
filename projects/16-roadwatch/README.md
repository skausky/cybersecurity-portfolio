# RoadWatch: Passive RF Detection of Surveillance Gear From a Moving Car

> Three ESP32 boards on a dashboard that listen to 2.4 GHz Wi-Fi and Bluetooth Low Energy while driving. They flag ALPR cameras, body cams and in-vehicle routers from the radio traffic those devices broadcast, then alert on an iPhone dashboard and a buzzer.

> **Scope:** Receive-only. Nothing is jammed, spoofed or connected to. The only transmissions are standard BLE scan requests and the link to my own phone. Capture logs stay local and are not published, because they contain other people's device addresses.

**Code:** [github.com/skausky/roadwatch](https://github.com/skausky/roadwatch)

## Overview

Surveillance hardware is a radio device first. ALPR cameras, body cameras and in-vehicle routers all broadcast Wi-Fi frames or BLE advertisements, and those broadcasts carry vendor-identifying fields: the **OUI** (first three bytes of the MAC address), SSIDs, BLE **company IDs** and **service UUIDs**. RoadWatch listens for those fields from a moving car and turns matches into prioritised alerts.

It is built on top of [OUI-SPY Unified](https://github.com/colonelpanichacks/oui-spy-unified-blue) by Colonel Panic, an open-source multi-mode firmware for a single ESP32-S3. **RoadWatch is my extension of it** into a three-board in-car system; see [What I built](#-what-i-built) for the split.

## Skills & Technologies

- **Embedded C++** on ESP32 / ESP32-S3: Wi-Fi promiscuous mode, 802.11 management-frame parsing, channel hopping
- **Bluetooth LE** (NimBLE): continuous active scanning, central/peripheral roles, Nordic UART Service links between boards
- **Device fingerprinting**: OUI tables, SSID rules, BLE company ID and service UUID matching, false-positive handling for shared chip vendors
- **Distributed embedded design**: three boards with independent reconnects, per-peer buffers, duplicate merging
- **Web Bluetooth** dashboard for iPhone (Bluefy), JSON protocol
- **Testing & field validation**: host-side C++ replay tests from real drive logs, Python miss-analysis tooling

## How it works

```
                 Car USB charger
   ┌──────────────────┼──────────────────┐
   ▼                  ▼                  ▼
RoadWatch-C        RoadWatch-A         RoadWatch-B
ESP32-S3 N8R2      WaveShare S3 + LCD  ESP32 + piezo buzzer
main Wi-Fi         hub: Wi-Fi sweep,   BLE scanner
sniffer (ch 11/6/1) screen, merging    (body cams, tags)
   │  BLE link  ──▶     ▲     ◀── BLE link  │
                        │
                 BLE (JSON lines)
                        ▼
              iPhone dashboard (Bluefy)
          alerts · sounds · device survey view
```

- **Board C** spends all its time on the three busiest Wi-Fi channels. **Board A** sweeps every channel, merges A and C hits on the same device (by MAC address), drives the screen and talks to the phone. **Board B** runs BLE scanning and the buzzer.
- Hits are classified into categories (ALPR, law-enforcement equipment, fleet router, low-priority consumer cameras). Each category has its own colour, sound and buzzer rhythm.
- A **priority queue** sheds low-value hits first under load, so important ones always reach the phone.

## What I built

On top of the upstream single-board firmware (about 6,000 lines across three commits):

- The three-board architecture: BLE links between boards, independent reconnects, per-peer outboxes, duplicate merging
- The screen UI on the WaveShare board and the iPhone dashboard (alerts, link status, survey/device view)
- The policy and road-signature modules: categories, SSID rules, an ignore list for fixed sites, alert priority
- A **survey mode** that logs everything heard, not just matches, so misses can be investigated after a drive
- A host-side replay test (`test_replay.cpp`) and `check_misses.py`, which lists devices that were heard but never alerted
- Channel plan and dwell time as build flags, so each board can be tuned without code changes

## Results and lessons from drive testing

- **The first drive missed things it should have caught.** A parked ALPR camera and a police vehicle were both missed, and one board logged nothing. Instead of guessing, I added survey mode and went back out to collect ground truth.
- **Found silent drop points in the alert path.** The survey showed a fleet router that *was* heard but never reached the phone. The cause was delivery: the alert queue and the outbox were overflowing during busy stretches. I fixed it with priority-based admission and counters in the heartbeat so drops are visible instead of silent.
- **Other field bugs fixed:** a GATT method mismatch between firmware and dashboard, channel dwell timing that missed beacons, an RSSI floor that filtered out real far-away hits, and a variable-length array on a task stack that risked overflow.
- **Hardware limits matter as much as code.** Many in-vehicle routers use 5 GHz, which the ESP32 can't hear. Mounting height changed range a lot. Common chip vendors (Espressif, Liteon) appear in both cameras and ordinary consumer gear, so OUI alone is not enough to flag them, and they're kept as low-confidence.
- Early warning is about **10–20 seconds at highway speed** for Wi-Fi targets. BLE from body cams confirms presence at short range rather than giving early warning.

## Defender's view

| | |
|---|---|
| **What leaks** | Factory MAC addresses (vendor OUI), descriptive SSIDs, BLE company IDs and service UUIDs. Anyone with a $10 board can tell what kind of device is nearby without connecting to it. |
| **Why it matters** | The same technique an attacker would use to find and target cameras or agency equipment (see [CamJam](../13-camjam/)). Fixed infrastructure and fleet vehicles are mappable from the road. |
| **Mitigation** | MAC address randomisation, generic or hidden SSIDs, turning off BLE advertising when not needed, 5 GHz-only operation where possible, and vendor pressure to stop broadcasting identifying fields. |
| **Detection** | Passive listening is undetectable by design. That's the lesson: the fix has to be on the transmitting side. |

## Credit

Base firmware: [OUI-SPY Unified](https://github.com/colonelpanichacks/oui-spy-unified-blue) by Colonel Panic, including the Flock-You detection mode and its signature set. RoadWatch is my multi-board extension, with the policy, survey, dashboard and testing work described above.
