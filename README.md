

## ✅ **Allsafe Access – Full Functionality List**

### 🔐 1. **User & Role Management** (`admin.go`, `core/admin/`, `roles.yaml`)

* Add user
* Delete user
* Update user role or password
* List users
* Define and manage roles with YAML (`roles.yaml`)

---

### 🔑 2. **Authentication & Sessions** (`sessions.go`, `core/auth/`, `core/sessions/`)

* User login
* User logout
* Session creation and validation
* Session expiration and storage (`~/.allsafe/session.json`)
* Password verification and hashing

---

### 📜 3. **Audit Log Monitoring** (`audit_tail.go`, `core/audit/`)

* Tail system audit logs (`/var/log/auth.log`, etc.)
* Real-time log monitoring
* Filter logs by user, IP, or keyword
* Detect suspicious activities (e.g., failed logins)

---

### 🧾 4. **Session Recording & Playback** (`core/record/`, `recordings/`)

* Record user activity/commands during sessions
* Store recorded logs under `recordings/`
* Playback or export session activity (for audit or compliance)

---

### 🧰 5. **Initialization & Setup** (`init.go`, `scripts/generate_cert.sh`)

* First-time setup
* Generate root/admin user
* Create config structure
* Generate certificates for secure connections

---

### 🔗 6. **SSH Access & Sharing** (`share_access.go`, `core/ssh/`)

* Establish secure SSH connections
* Temporarily share server access between users
* Enforce role-based access to servers (`servers.yaml`)

---

### ⚙️ 7. **Configuration Management** (`core/config/`, `config/`)

* Parse and validate `roles.yaml` (role definitions)
* Parse `servers.yaml` (IP, hostname, allowed roles)
* Dynamically control access permissions via config

---

### 🧩 8. **Plugin Support** (`core/plugins/`)

* Load custom plugins for new features
* Extend CLI or core logic without modifying base code

---

### 📦 9. **Debian Packaging** (`package/debian/`)

* Package the tool for `.deb` installations
* Allow system-wide deployment via apt or dpkg

---

### 🧼 10. **Maintenance Scripts** (`scripts/`)

* `cleanup.sh`: remove temp/log/session files
* `generate_cert.sh`: generate secure TLS/SSH certs

---

### 🧪 11. **Testing & Validation** (`test/`, `*_test.go`)

* Unit tests for each core module
* Integration testing of CLI behavior

