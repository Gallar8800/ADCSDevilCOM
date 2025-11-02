# ADCSDevilCOM
# ADCSDevilCOM
A C# tool for requesting certificates from ADCS using DCOM over SMB. This tool allows you to remotely request X.509 certificates from CA server using the MS-WCCE protocol over DCOM and It bypasses the traditional endpoint mapper requirement by using SMB directly.

> [!WARNING]
> Use only in environments where you have explicit authorization. Unauthorized use may be illegal.

## What This Tool Can Do

- **Request certificates remotely** via DCOM/SMB
- **Generate RSA key pairs** (2048/4096 bits)
- **Create Certificate Signing Requests (CSRs)**
- **Add Subject Alternative Names** (UPN/DNS) for ESC1 exploitation
- **Retrieve pending certificates with CA Manager Approval** by request ID
- **Export certificates** as PFX (with private key) or CER files

### Authentication
- Use explicit credentials (username/password/domain)
- Use current Windows user context

### Attack Scenarios
- **ESC1**: Request certificates with arbitrary UPNs to impersonate other users
- **ESC6**: Abuse any template when EDITF_ATTRIBUTESUBJECTALTNAME2 is set
- **Persistence**: Create long-lived certificates for backdoor access

---

## Technical Details
See the [Technical Details]() for how ADCSDevilCOM works.

---

## Usecases
See the [Usecases]() for how ADCSDevilCOM can be used.

---

### Build

```bash
# Clone or download the tool
git clone https://github.com/7hePr0fess0r/ADCSDevilCOM
cd ADCSDevilCOM

# Build (For testing I used .NET 9 SDK)
dotnet build

# Publish (optional)
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

---

## Usage

### Command-Line Syntax

```bash
ADCSDevilCOM.exe -target dc01.corp.local -ca DC01-CA -template VulnerableTemplate -upn administrator@corp.local [OPTIONS]
```

### Required Parameters

- `-target <server>` - CA server hostname or IP address
- `-ca <name>` - Certificate Authority name
- `-template <name>` - Certificate template

### Optional Parameters

**Authentication:**
- `-username <user>` - Username for authentication
- `-password <pass>` - Password for authentication  
- `-domain <domain>` - Domain name

**Certificate Request:**
- `-subject <dn>` - Subject DN (auto-generated as "CN={username}" if omitted)
- `-upn <upn>` - User Principal Name for SAN (for ESC1 attacks)
- `-dns <name>` - DNS name for SAN (for computer/web certificates)
- `-keysize <bits>` - RSA key size (default: 2048)
- `-out <file>` - Output filename prefix (defaults to username)

**Certificate Retrieval:**
- `-retrieve <id>` - Retrieve certificate by request ID

**Help:**
- `-h` or `-help` - Display help information

---

## Output Files

### Successful Immediate Issuance
- `{username}.pfx` or `{custom_name}.pfx` - Certificate with private key

### Pending Requests
- `{username}.key` - Private key saved for later retrieval
- Use `-retrieve` command after approval to get certificate

### Retrieved Certificates
- `request_{ID}.pfx` - Certificate with private key (if .key file found)
- `request_{ID}.cer` - Certificate only (if no private key available)

---
