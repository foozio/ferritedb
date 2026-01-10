# Specification: Realtime Infrastructure Stability and Resilience

## 1. Overview
This track focuses on hardening the existing Realtime WebSocket infrastructure in FerriteDB. The primary goal is to ensure connection stability and proactive cleanup of dead connections through a configurable heartbeat mechanism and defined client-side reconnect strategies.

## 2. Functional Requirements
- **Server-Side Heartbeat:**
    - Implement a periodic "Ping" message sent from the server to all connected WebSocket clients.
    - Track the number of missed "Pong" responses from each client.
    - Proactively close connections that exceed a configurable threshold of missed responses.
- **Client-Side Reconnect Support:**
    - Define and document the expected behavior for clients to perform exponential backoff reconnects.
    - Ensure server-side cleanup (subscriptions, manager state) is immediate upon connection closure (initiated by server or client).
- **Configuration:**
    - Add `heartbeat_interval` (seconds) to the global `ferritedb.toml` configuration.
    - Add `heartbeat_timeout_count` (maximum missed pongs) to the global `ferritedb.toml` configuration.

## 3. Non-Functional Requirements
- **Performance:** The heartbeat mechanism must scale efficiently to handle hundreds of concurrent WebSocket connections without significant CPU overhead.
- **Observability:** Log connection closures due to heartbeat timeouts as warnings for operational visibility.

## 4. Acceptance Criteria
- [ ] WebSocket connections remain alive during active sessions.
- [ ] Connections are closed by the server if the client stops responding to pings within the configured threshold.
- [ ] Heartbeat parameters can be modified via `ferritedb.toml` and are correctly respected by the server.
- [ ] Internal `RealtimeManager` state is correctly pruned when a connection is closed due to a timeout.

## 5. Out of Scope
- Implementing rate limiting per user/IP (deferred to a future track).
- Hardening WebSocket message payloads (focus is purely on connection stability).
