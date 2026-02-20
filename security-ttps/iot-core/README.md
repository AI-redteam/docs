# IoT Core

## Overview

IoT Core provides MQTT-based device communication with registries, devices, and brokers. Authentication supports X.509 certificates and username/password. Topic wildcards and device impersonation are the primary attack vectors.

## Authentication Mechanisms

### X.509 Certificates
- Mutual TLS (mTLS) for connection
- Registry-level and device-level certificates
- Certificate priority over password auth

### Username/Password
- Username = Device ID or Registry ID
- Password: minimum 14 chars, 3 of 4 character types required
- Used as fallback when certificates unavailable

---

## Initial Access

### Device Credential Theft

Leaked device credentials (certificates or passwords) allow:
- Authenticate as the device
- Publish to device topics
- Subscribe to device command topics
- Access registry-level topics if registry credentials are used

### Wildcard Subscription

```
# Subscribe to ALL topics in a registry
mosquitto_sub -t '#' -h mqtt.cloud.yandex.net -p 8883 \
  --cert device.crt --key device.key --cafile ca.pem
```

The `#` wildcard matches all topics — intercepts all device telemetry and commands in the registry.

---

## Post-Exploitation

### Message Injection

Publish false telemetry or commands:

```bash
# Publish fake sensor data
mosquitto_pub -t '$registries/<reg-id>/events' \
  -m '{"temperature": 99.9}' \
  -h mqtt.cloud.yandex.net -p 8883 \
  --cert device.crt --key device.key --cafile ca.pem
```

### Data Interception

Subscribe to command topics to intercept commands sent to devices:

```bash
mosquitto_sub -t '$devices/<device-id>/commands/#' \
  -h mqtt.cloud.yandex.net -p 8883 \
  --cert device.crt --key device.key --cafile ca.pem
```

---

## Persistence

### Permanent Topic Subscriptions

MQTT permanent subscriptions persist across disconnects — the device receives messages sent while offline upon reconnection.

### Broker Namespace

Brokers provide isolated MQTT namespaces with client-based auth (not device-centric). A compromised broker credential provides an independent persistence channel.

---

## Exfiltration

Publish data to MQTT topics that an external subscriber reads:
- Encode exfiltrated data in MQTT messages
- Use QoS 1 for reliable delivery
- Message payload limit: 256KB per message

---

## Enumeration

```bash
yc iot registry list --folder-id <folder-id>
yc iot device list --registry-id <reg-id>
yc iot broker list --folder-id <folder-id>
```

---

## Detection

| Event | Audit Key |
|---|---|
| Device creation | `iot-core.devices.create` |
| Registry creation | `iot-core.registries.create` |
| Certificate changes | `iot-core.devices.addCertificate` |

## Defensive Recommendations

1. Use X.509 certificates instead of passwords
2. Restrict topic permissions per device (no wildcard access)
3. Monitor for wildcard subscriptions
4. Rotate certificates regularly
5. Disable unused devices/registries
6. Use separate brokers for different trust levels
