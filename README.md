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
