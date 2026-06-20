# Detection: New Listening Port Opened

## Objective

Detect when a Windows endpoint opens a new listening port. This helps identify new services or applications that may expose the host to the network.

## MITRE ATT&CK

- Technique: Network Service Discovery / Network Activity Monitoring
- Tactic: Discovery

## Log Source

- Wazuh Syscollector
- Port inventory events
- `type: dbsync_ports`

## Rule Logic

Rule `100201` triggers when Wazuh Syscollector detects a new port entry with the operation type `INSERTED`.

```xml
<rule id="100201" level="7">
  <if_sid>100200</if_sid>
  <field name="operation_type">INSERTED</field>
  <description>
    Host opened a new listening port: $(port.local_port) on $(port.local_ip)
  </description>
  <group>network_ports,opened_port,</group>
</rule>

```

![Rule 100201 Alert](../screenshots/100201-new-listening-port.png)