Allsafe Access is a comprehensive remote access solution that consists of three main components: `allsafe-auth`, `allsafe-cli`, and `allsafe-proxy`. Together, these components provide a secure, auditable, and managed way to access remote systems.

`allsafe-auth` is the Certificate Authority (CA) for the system. It is responsible for generating and managing the self-signed Root CA and issuing certificates for the other components. The `allsafe-auth` CLI can also import an existing external CA, allowing it to integrate into an organization's existing Public Key Infrastructure (PKI). It also issues sample certificates for the proxy and agent for demonstration purposes.

`allsafe-proxy` acts as a central gateway, mediating all communication between clients and agents. It enforces authentication, authorization, and audit logging to ensure secure and auditable remote access. The proxy manages the registration and lifecycle of remote agents using heartbeats and enforces fine-grained, role-based access control (RBAC). It provides administrative endpoints for managing users via secure invitations, listing active sessions, and terminating sessions. The proxy also logs security events to a SQLite database for monitoring and compliance.

`allsafe-cli` is the command-line client for the Allsafe Access system. It allows users to securely authenticate with the `allsafe-proxy` and connect to remote agents. The CLI offers an interactive shell with features like auto-completion and command history for a user-friendly experience. Users can list all accessible nodes and connect to a remote agent's interactive shell. The `allsafe-cli` also supports multi-factor authentication (MFA) to enhance security.


# Allsafe Proxy

`allsafe-proxy` is the central component of the Allsafe Access system. It acts as a secure gateway that mediates all communication between client applications (like the `allsafe-cli`) and remote agents. The proxy enforces authentication, authorization, and audit logging to ensure all remote access is secure and auditable.

## Features

  * **Secure TLS Gateway**: The proxy uses mTLS to secure communication with both clients and agents, verifying their certificates to establish a chain of trust.
  * **Agent Management**: Manages the registration and lifecycle of remote agents, using heartbeats to track their status and availability.
  * **Centralized Authentication**: Authenticates users against a database, supporting both password-based and TOTP-based multi-factor authentication.
  * **Role-Based Access Control (RBAC)**: Enforces fine-grained access policies, allowing administrators to control which users can access which agents and with what remote user accounts.
  * **Auditing**: Logs a wide range of security events to a SQLite database, including authentication attempts, successful logins, command executions, and session starts/ends. The audit log is a core component for monitoring and compliance.
  * **Interactive Shell Relay**: Acts as a secure, bidirectional relay for interactive shell sessions between the CLI and remote agents via WebSockets.
  * **Session Management**: Provides administrative endpoints to list and terminate active user sessions.
  * **User Provisioning via Invitation**: Allows administrators to create secure, one-time invitation links for new users to set their password and, if enabled, configure MFA.

## Getting Started

### Prerequisites

To run the `allsafe-proxy`, you'll need:

  * A binary of the `allsafe-proxy` application.
  * A configuration file (`allsafe-proxy.yaml`).
  * The TLS certificate, key, and CA certificate files (`proxy.crt`, `proxy.key`, `ca.crt`).
  * A SQLite database file for user management (`allsafe_admin.db`).
  * A directory for role configuration files (`roles/`).
  * A template file for the invitation form (`invite_form.html`).

The proxy will look for its configuration file in the following locations, in order of precedence:

1.  The path specified by the `--config` flag.
2.  `/etc/allsafe-proxy/`.
3.  `$HOME/.allsafe-proxy/`.
4.  The current directory (`./`).

A typical configuration file looks like this:

```yaml
listen_address: ":8080"
cert_file: "/etc/allsafe-proxy/proxy.crt"
key_file: "/etc/allsafe-proxy/proxy.key"
ca_cert_file: "/etc/allsafe-proxy/ca.crt"
agent_listen_port: 8081
agent_heartbeat_timeout_minutes: 5
registration_token: "a-secure-agent-token"
require_client_cert_for_cli: false
users_config_path: "/etc/allsafe-proxy/allsafe_admin.db"
roles_config_dir: "/etc/allsafe-access/role/"
invite_url_base: "https://localhost:8080"
admin_token: "a-very-secret-admin-token"
secret_key: "a-strong-token-signing-key" # This is a CRITICAL secret
```

**Note**: The `secret_key` is a new, critical configuration item used to sign invitation tokens. It must be set and kept confidential.

### Running the Proxy

To start the proxy, simply execute the binary.

```bash
allsafe-proxy
```

The proxy will load its configuration, establish a database connection, and start listening for HTTPS and WebSocket connections. It also starts background tasks to clean up old agents and periodically reload user and role configurations.

### Key Endpoints

The proxy exposes several key API endpoints for various functions:

#### Agent Endpoints

  * **`/register`**: Agents send a registration request to this endpoint to register with the proxy.
  * **`/heartbeat`**: Agents periodically send heartbeats here to confirm they are active.
  * **`/run-command`**: Used to forward commands to an agent.
  * **`/audit/agent`**: Agents send a request to this endpoint to log security and activity events to the proxy's central audit database.

#### CLI Endpoints

  * **`/cli/auth`**: Used by the `allsafe-cli` to authenticate a user with a username and password (and optional TOTP code).
  * **`/cli/nodes`**: Returns a list of agents the authenticated user is authorized to access.
  * **`/cli/shell`**: Establishes a WebSocket connection for an interactive shell session.

#### Administrative Endpoints

  * **`/invite`**: A public-facing endpoint for users to set a password from an invitation link.
  * **`/set-password`**: The form submission endpoint for setting a new user's password.
  * **`/admin/sessions`**: An authenticated endpoint for administrators to list all active sessions.
  * **`/admin/authenticated-users`**: An authenticated endpoint to list all currently authenticated users.
  * **`/admin/terminate-session`**: An authenticated endpoint for administrators to forcibly terminate a user's session by username.

#### Core Concepts

  * **Agents and Sessions**: The proxy manages `AgentInfo` structs for registered agents and `ActiveSession` structs for ongoing user sessions.
  * **Auditing**: All key actions, such as login attempts, session starts, and command executions, are logged to the `audit_events` table in the database.
  * **Configuration Reloading**: The proxy automatically reloads user and role configurations from the filesystem every 30 seconds without requiring a restart, allowing for dynamic policy updates.
  * **Security Policies**: `require_client_cert_for_cli` can be set to `true` to enforce a higher level of security by requiring client certificates for all CLI connections.
