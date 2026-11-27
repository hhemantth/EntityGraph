# EntityGraph

EntityGraph is a local-first investigation workspace for turning exported security events into an interactive entity graph. It runs entirely in the browser and does not send event data to a server.

## Start

1. Extract the project folder.
2. Open `index.html` in Microsoft Edge or Google Chrome.
3. Select **Import events** and choose one or more CSV exports.

No installation, build step, tenant integration, or web service is required.

## Supported workflow

- Import Sentinel, Defender, or other CSV event exports.
- Detect accounts, devices, IP addresses, processes, files, hashes, URLs, domains, alerts, email addresses, and cloud resources.
- Aggregate repeated relationships while retaining source rows as evidence.
- Search, pan, zoom, drag, filter, hide, pin, and re-layout entities.
- Use the time window to narrow the graph to a relevant period.
- Shift-click multiple nodes to resolve identifiers that represent the same entity.
- Preserve aliases, properties, notes, event counts, and evidence through a merge.
- Route later imports that contain resolved identifiers to the canonical entity.
- Undo merges in reverse order.
- Select two entities and calculate their shortest path.
- Add or edit entities and relationships manually.
- Add analyst notes, risk, and investigation status.
- Save and reopen an investigation in the browser.
- Export and restore the full investigation as JSON.
- Export the graph as PNG and entities or relationships as CSV.

## Entity resolution

Account fields such as `AccountUPN`, `AccountDisplayName`, and `AccountId` are initially kept as distinct identifiers. The same applies to `DeviceName` and `DeviceId`. This preserves the imported evidence and avoids assuming that two values are identical.

To resolve them:

1. Select the first entity.
2. Hold **Shift** and select the other identifiers.
3. Select **Resolve same entity**.
4. Choose the starting identity, canonical label, and canonical type.
5. Select **Merge and resolve**.

The original identifiers remain searchable as aliases. All affected relationships are rebuilt against the canonical entity. Equivalent relationships are deduplicated and their counts and evidence are combined.

## CSV fields

EntityGraph recognizes common field names, including:

- `DeviceName`, `DeviceId`, `Computer`, `HostName`
- `AccountUPN`, `AccountDisplayName`, `AccountId`, `AccountName`
- `RemoteIP`, `LocalIP`, `SourceIP`, `DestinationIP`
- `InitiatingProcessFileName`, `ProcessName`, `FileName`
- `SHA256`, `SHA1`, `MD5`
- `URL`, `RemoteUrl`, `Domain`, `DnsQuery`
- `AlertId`, `IncidentId`, `AlertName`
- `SenderFromAddress`, `RecipientEmailAddress`
- `ResourceId`, `ServicePrincipalId`, `ApplicationId`
- `Timestamp`, `TimeGenerated`, `EventTime`

A small example is included in `sample-data/device-network-events.csv`. It is not loaded automatically; the application always starts with an empty canvas.

## Investigation files

The JSON export uses the `EntityGraph Investigation v2` format and includes:

- Investigation metadata
- Normalized entities and relationships
- Original evidence rows
- Analyst notes and assessments
- Alias-to-canonical resolution map
- Node positions and pinned state

Use JSON export for portable case files. Browser saves remain in the browser profile on the same workstation.

## Data handling

EntityGraph has no network dependency and makes no outbound requests. Imported files are processed in memory. Browser saves use local storage. Clearing browser site data can remove those saves, so export important investigations as JSON.

## Project files

- `index.html` — application shell and controls
- `styles.css` — visual design and responsive layout
- `app.js` — imports, graph model, entity resolution, rendering, persistence, and exports
- `assets/` — EntityGraph logo and favicon
- `sample-data/` — optional test data
- `tests/` — lightweight verification scripts
