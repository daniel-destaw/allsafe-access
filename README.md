**Allsafe Access: A Comprehensive Remote Access Solution**

Allsafe Access is a comprehensive remote access solution that consists of three main components: `allsafe-auth`, `allsafe-cli`, and `allsafe-proxy`. Together, these components provide a secure, auditable, and managed way to access remote systems.

**`allsafe-auth`**
`allsafe-auth` is the Certificate Authority (CA) for the system. It is responsible for generating and managing the self-signed Root CA and issuing certificates for the other components. The `allsafe-auth` CLI can also import an existing external CA, allowing it to integrate into an organization's existing Public Key Infrastructure (PKI). It also issues sample certificates for the proxy and agent for demonstration purposes.

**`allsafe-proxy`**
`allsafe-proxy` acts as a central gateway, mediating all communication between clients and agents. It enforces authentication, authorization, and audit logging to ensure secure and auditable remote access. The proxy manages the registration and lifecycle of remote agents using heartbeats and enforces fine-grained, role-based access control (RBAC). It provides administrative endpoints for managing users via secure invitations, listing active sessions, and terminating sessions. The proxy also logs security events to a SQLite database for monitoring and compliance.

**`allsafe-cli`**
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


# Allsafe CLI

`allsafe-cli` is the command-line client for the Allsafe Access system. It provides administrators and users with a secure, authenticated, and audited way to interact with remote agents through the central Allsafe Proxy. The CLI offers a user-friendly, interactive experience with features like auto-completion and command history.

## Features

  * **Secure Authentication**: Authenticates with the Allsafe Proxy using a username and password, with support for multi-factor authentication (MFA) to enhance security.
  * **Interactive Shell**: Provides an interactive, `go-prompt`-based shell for a more intuitive user experience.
  * **Node Discovery**: Lists all available agents (nodes) that the authenticated user is authorized to access.
  * **Direct Access**: Allows users to connect directly to an interactive shell on a remote agent. The CLI securely handles the WebSocket connection and stream forwarding.
  * **User Impersonation**: During a connection, the CLI can specify a `remote_user` to "impersonate," allowing the session on the agent to run under the context of that specific local user.
  * **Configuration-driven**: Uses an `allsafe-cli.yaml` file to store the proxy address, removing the need to provide it with a flag for every command.

## Getting Started

### Prerequisites

To use the CLI, you must have the `allsafe-cli` binary and an `allsafe-cli.yaml` configuration file. The CLI will look for the config file in the following locations, in order:

1.  `./`
2.  `../`
3.  `/etc/allsafe-cli/`

A typical configuration file looks like this:

```yaml
proxy_url: "https://your-proxy.example.com:8080"
```

If you don't use a configuration file, you must provide the proxy address with the `--proxy` flag for all commands.

### Usage

The `allsafe-cli` can be used in two main modes: a single-command mode or an interactive shell.

#### Single-Command Mode

You can execute a command directly by passing it as an argument.

**Login**

```bash
allsafe-cli login
```

This command will prompt you for your username and password, and an MFA code if required. Once authenticated, your session is ready for subsequent commands.

**List Nodes**

```bash
allsafe-cli list-nodes
```

Displays a list of all agents that are registered with the proxy and that you are authorized to access.

**Connect to an Agent**

```bash
allsafe-cli access <agent_id> <remote_user>
```

Connects to the interactive shell on the specified `<agent_id>`, and attempts to log in as the `<remote_user>`.

#### Interactive Shell Mode

For a more streamlined experience, simply run the `allsafe-cli` binary without any arguments to enter the interactive shell.

```bash
$ allsafe-cli
```

This will start an interactive session with the following prompt:

```
Welcome to Allsafe CLI. Please log in.
Username:
Password:
...
```

Once logged in, the prompt will change to reflect your username:

```bash
johndoe@allsafe-access$ 
```

The interactive shell supports the following commands:

  * `list-nodes`: Lists available agents.
  * `access <agent_id> <remote_user>`: Connects to a remote agent.
  * `refresh`: Refreshes the list of available agents.
  * `toggle-hint`: Enables or disables auto-completion hints.
  * `exit`: Exits the interactive shell.

**Auto-Completion**

The interactive shell provides auto-completion for commands and agent IDs. Pressing the `Tab` key will suggest available commands and, when using the `access` command, will show a list of accessible `agent_id`s.



# Allsafe Auth CLI

The `allsafe-auth` CLI is the command-line interface for the Allsafe Access authentication and identity management service. It's a critical tool for setting up the secure foundation of your Allsafe Access deployment by managing the cryptographic keys and certificates.

Its primary function is to initialize a Certificate Authority (CA), which will be used to issue and sign certificates for all components of the Allsafe Access system (e.g., the proxy, agents, and clients). This ensures all communication is secured with mutual TLS (mTLS), where each component can verify the identity of the others.

## Features

  * **Certificate Authority (CA) Initialization**: Creates a self-signed Root CA certificate and private key, or imports an existing one. This Root CA is the single source of trust for your entire Allsafe Access deployment.
  * **Certificate Issuance**: Automatically generates and signs certificates and private keys for the Allsafe Proxy and Agents using the established Root CA.
  * **Interactive Prompts**: Guides administrators through the certificate creation process with interactive prompts for required details, such as common names and organizations.
  * **Configurable Certificates**: Allows customization of key sizes and certificate lifetimes for both the Root CA and component certificates.
  * **External CA Support**: You can import an existing external Root or Intermediate CA, seamlessly integrating Allsafe Access into your existing Public Key Infrastructure (PKI).
  * **Idempotent Operations**: The `init-ca` command won't overwrite an existing CA by default, preventing accidental data loss. A `--force-rewrite` flag is available for intentional regeneration.

## Getting Started

### Prerequisites

You'll need to have the `allsafe-auth` binary and an `allsafe-auth.yaml` configuration file. The CLI will look for the config file in the following locations, in order:

1.  `/etc/allsafe-auth/`
2.  `$HOME/.allsafe-auth/`
3.  The current directory (`./`)

A typical configuration file looks like this:

```yaml
certs_dir: "configs/certs"
root_ca_lifetime_years: 10
root_ca_key_size: 4096
component_cert_lifetime_years: 1
component_cert_key_size: 2048
```

### Command Line Usage

The `allsafe-auth` CLI currently has one main command: `init-ca`.

### Initialize the Certificate Authority (`init-ca`)

This command is the first step in setting up a new Allsafe Access deployment. It will create a Root CA and then issue sample certificates for the proxy and an agent.

#### Creating a New Self-Signed CA

If you don't have an existing CA, run the command and follow the interactive prompts to generate a new one.

```bash
allsafe-auth init-ca
```

**Example output:**

```
Allsafe Auth Service: Initializing Root CA...
Certs directory 'configs/certs' created successfully.
Generating new Root CA certificate and key...
Self-signed Root CA generated.
Root CA is ready.

Issuing sample certificates for demonstration...
Please provide the following details for your Proxy Certificate:
? Common Name for Proxy Certificate (e.g., 127.0.0.1 or proxy.allsafe.com):  [127.0.0.1]
Issued proxy.crt and .key
...
```

#### Importing an External CA

If you're using an existing PKI, you can import your CA certificate and key. The CLI will then use this CA to sign the Allsafe component certificates.

```bash
allsafe-auth init-ca \
    --external-ca-cert /path/to/my-root-ca.crt \
    --external-ca-key /path/to/my-root-ca.key
```

### Overwriting an Existing CA

By default, `init-ca` will not overwrite an existing CA. To force a new CA to be generated and all existing certificates to be overwritten, use the `--force-rewrite` flag.

```bash
allsafe-auth init-ca --force-rewrite
```


# Allsafe Agent

The `allsafe-agent` is a component of the Allsafe Access system, designed to be deployed on remote servers and devices. Its primary function is to securely connect to a central Allsafe Proxy, allowing authenticated and authorized administrators to execute commands and access interactive shell sessions on the host machine.

The agent uses mutual TLS (mTLS) for all communications with the proxy, ensuring that connections are encrypted and that both the agent and proxy can verify each other's identities. This provides a strong security foundation for remote access.

## Features

  * **Secure Registration & Heartbeats**: Registers itself with the central proxy using a one-time token and periodically sends heartbeats to maintain its status as an active and healthy component.
  * **Mutual TLS (mTLS) Authentication**: All network communication is secured with mTLS, requiring both the agent and the proxy to present valid certificates from a trusted Certificate Authority (CA).
  * **Remote Command Execution**: Receives and executes one-off commands from the proxy in a secure manner.
  * **Interactive Shell Sessions**: Provides a WebSocket-based interactive shell that allows administrators to gain direct shell access to the host.
  * **User Impersonation**: The interactive shell can be configured to run as a specific local user, ensuring that all actions respect the target user's permissions and environment.
  * **Configurable Shell Path**: The path to the shell executable can be specified in the configuration, allowing for flexibility (e.g., using `bash`, `zsh`, `sh`, etc.).
  * **Maximum Auditing**: When enabled, the agent captures and logs every command entered in an interactive session, providing a detailed audit trail. This is particularly useful for security compliance and incident investigations.

## Getting Started

### Prerequisites

To run the agent, you need to provide a set of TLS certificates and keys for mTLS. These include:

  * A client certificate (`agent.crt`) and private key (`agent.key`) for the agent to present to the proxy.
  * The Certificate Authority's root certificate (`ca.crt`) that signed both the proxy's and agent's certificates.

These files should be configured in the `allsafe-agent.yaml` configuration file.

### Configuration

The agent is configured using a YAML file named `allsafe-agent.yaml`. The CLI tool will look for this file in the following locations, in order:

1.  `/etc/allsafe-agent/`
2.  `$HOME/.allsafe-agent/`
3.  The current directory (`./`)

A typical configuration file looks like this:

```yaml
id: "agent-01"
proxy_url: "https://your-proxy.example.com:8080"
listen_address: ":8081"
cert_file: "/etc/allsafe-agent/agent.crt"
key_file: "/etc/allsafe-agent/agent.key"
ca_cert_file: "/etc/allsafe-agent/ca.crt"
registration_token: "your-secret-registration-token"
labels:
  os: "linux"
  env: "production"
heartbeat_interval_seconds: 30
maximum_auditing_enabled: true
shell_path: "/bin/bash"
```

### Command Line Usage

While a configuration file is the recommended way to run the agent, all settings can also be provided via command-line flags.

```bash
# Start the agent with all settings specified via flags
allsafe-agent \
    --id "agent-01" \
    --proxy-url "https://your-proxy.example.com:8080" \
    --listen-address ":8081" \
    --cert "/path/to/agent.crt" \
    --key "/path/to/agent.key" \
    --cacert "/path/to/ca.crt" \
    --token "your-secret-registration-token" \
    --labels "os=linux,env=production" \
    --heartbeat-interval 30 \
    --maximum-auditing-enabled \
    --shell-path "/bin/bash"
```

### Running the Agent

To start the agent, simply execute the binary. It will automatically load its configuration and begin the registration and heartbeat process.

```bash
allsafe-agent
```


# Allsafe Admin CLI

`allsafe-admin` is a command-line tool designed for administrators to manage users, sessions, and audit logs for the Allsafe Access proxy. It provides a robust interface for common administrative tasks, including user creation, password resets, and monitoring.

## Features

  * **User Management**: Add, delete, list, and view details for user accounts.
  * **Password Resets**: Easily generate a new, one-time invitation URL to reset a user's password.
  * **Multi-Factor Authentication (MFA)**: Support for setting up TOTP MFA for new users during creation.
  * **Session Control**: List active sessions and terminate sessions for a specific user to force a logout.
  * **Audit Logging**: View and filter audit logs to monitor user actions and administrative events.
  * **Configuration-driven**: Uses a YAML configuration file (`allsafe-proxy.yaml`) to securely handle connection details and secrets.

## Getting Started

### Prerequisites

Before using the CLI, ensure you have the `allsafe-proxy.yaml` configuration file set up in one of the expected locations (`./`, `../`, or `/etc/allsafe-proxy/`). This file must contain the `secret_key` and `admin_token` used by the proxy to securely sign invitations and authenticate administrative requests.

### Usage

The CLI is structured around a few top-level commands: `user`, `sessions`, and `audit`.

```bash
allsafe-admin [command]
```

### User Management

Manage user accounts with the `user` command.

#### Add a new user

Creates a new user and generates a unique invitation URL for them to set their password.

```bash
# Add a basic user
allsafe-admin user add johndoe

# Add a user with a specific role and password policy
allsafe-admin user add jane_admin --role admin --policy hard

# Add a user with TOTP MFA enabled
allsafe-admin user add security_user --role user --mfa totp
```

**Options:**

  * `--role`: (default `user`) The user's role (`user` or `admin`).
  * `--policy`: (default `none`) The password complexity policy (`none`, `medium`, or `hard`).
  * `--mfa`: (default `none`) The MFA type (`totp` or `none`).

#### Delete a user

Permanently removes a user account and their associated data. This action requires confirmation.

```bash
allsafe-admin user delete johndoe
```

#### Reset a user's password

Generates a new invitation URL, effectively invalidating the old password and forcing the user to set a new one.

```bash
allsafe-admin user reset-password johndoe
```

#### List all users

Displays a table of all users in the system.

```bash
allsafe-admin user list
```

### Session Management

Control and monitor active sessions with the `sessions` command.

#### List active sessions

Fetches and displays a list of all currently active sessions on the proxy.

```bash
allsafe-admin sessions list-active
```

#### Terminate a user's sessions

Forces a specific user to be logged out by terminating all of their active sessions.

```bash
allsafe-admin sessions terminate johndoe
```

### Audit Logs

View and filter audit logs with the `audit` command.

#### List audit logs

Displays a list of audit events. Use flags to filter the results.

```bash
# View the 20 most recent logs
allsafe-admin audit list --limit 20

# Filter logs by a specific user
allsafe-admin audit list --user-id johndoe

# Filter by a specific event type (e.g., ADMIN_ACTION)
allsafe-admin audit list --event-type ADMIN_ACTION

# Search for logs containing a keyword
allsafe-admin audit list --search "password"
```

**Options:**

  * `--event-type`: Filter by event type.
  * `--user-id`: Filter by the user ID.
  * `--search`: Search for a keyword in the action or details.
  * `--limit`: (default `10`) The maximum number of logs to display.
