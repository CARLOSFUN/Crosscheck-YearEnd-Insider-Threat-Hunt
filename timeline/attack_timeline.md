# Crosscheck Attack Timeline

| Timestamp UTC | Endpoint | User or Remote Session | Activity | Evidence |
|---|---|---|---|---|
| 2025-12-03T06:27:31.1857946Z | sys1-dept | Remote session from 192.168.0.110 | First outbound connectivity test | Flag 07 |
| 2025-12-03T07:25:15.6288106Z | sys1-dept | Remote session context | Performance review access observed | Flag 12 |
| 2025-12-03T07:25:39.1653621Z | sys1-dept | Remote session context | Sensitive read of approved bonus artifact | Flag 13 |
| 2025-12-03T07:26:28.5959592Z | sys1-dept | Remote session context | Outbound POST transfer test timestamp | Flag 15 |
| 2025-12-04T03:11:58.6027696Z | main1-srvr | YE-FINANCEREVIE | Approved bonus artifact accessed on second endpoint | Flag 18 |
| 2025-12-04T03:15:29.2597235Z | main1-srvr | Final phase | Staging activity in InternalReferences | Flag 21 |
| TBD | main1-srvr | Final phase | Final outbound attempt to 54.83.21.156 | Flag 22 |
