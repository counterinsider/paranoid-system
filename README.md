# Overview

Paranoid System is a Linux system launch and runtime integrity verification utilities, leveraging hardware-based (Trusted Platform Module, TPM) and software-based (Linux Integrity Measurement Architecture, IMA subsystem) security technologies to ensure that system is in trusted state, from platform firmware components, bootloader, OS kernel to separate system and user files, protecting boot as well as runtime system integrity with support for remote attestation.

# This work is experimental

The project is in **early development stage with limited functionality** and active research on runtime kernel and firmware security is ongoing. The main idea behind is to build system launch and runtime integrity remote attestation tool for desktop workstations, primarily **focused on ease of use available to non-advanced Linux users**. Currently, there is no Linux distribution offering TPM and IMA-based protections out of the box. Users with administrator skills need to go through configuration steps and constraints implied by IMA subsystem. More advanced projects with similar functionality exist like:

* [Keylime](https://github.com/keylime/keylime)
* [TrenchBoot](https://github.com/TrenchBoot/documentation)
* [safeboot](https://github.com/osresearch/safeboot)
* [ibmacs](https://sourceforge.net/projects/ibmtpm20acs/)
* [wolfBoot](https://github.com/wolfSSL/wolfBoot) and [wolfTpm](https://github.com/wolfSSL/wolfTPM) library

but they require complex deployments and system tampering, even bootloader, kernel patching, so not user-oriented.

# Introduction

Paranoid System represents three programs:

- `paranoid-boot` - system launch integrity measurement with TPM and IMA. Program runs on every system startup and asserts boot integrity against previously established baselines.

- `paranoid-srv` - HTTP attestation server verifying clients system integrity, including TPM quotes.

- `paranoid-rt` - daemon which continuously measures runtime system integrity with support for remote attestation.

# Installation

### Client

The simplest method to install Paranoid System is just to download pre-compiled `paranoid-boot`, `paranoid-rt` binaries from the repository [releases page](https://github.com/counterinsider/paranoid-system/releases), then make them available in `PATH`:

```bash
sudo install -m 0755 -o root -g root paranoid-{boot,rt} /sbin
```

`paranoid-boot` is required to be launched on every system startup. Currently, it is implemented with the following `systemd` service:

```bash
echo '
[Unit]
Description=System launch integrity measurement with TPM and IMA
Requires=network.target
After=network.target

[Service]
ExecStart=/sbin/paranoid-boot attest

[Install]
WantedBy=multi-user.target
' | sudo tee /etc/system/systemd/paranoid-boot.service

sudo systemctl daemon-reload
sudo systemctl enable paranoid-boot.service
```

#### Dependencies

Only `tpm2-tss` library (TSS 2.0 Enhanced System API) is required for client TPM interaction. You have to install `tpm2-tools` package using your package manager:
```bash
# For Debian-based distributions
sudo apt-get install tpm2-tools
# For RPM-based distributions
sudo dnf install tpm2-tools
```

#### Build from source

Or you can compile the binaries from source code locally. First, you have to install [Rust toolchain](https://rustup.rs/). Also ensure that `tpm2-tss` dependency is satisfied. Then:
```bash
git clone https://github.com/counterinsider/paranoid-system
cd paranoid-system
cargo build -r

sudo install -m 0755 -o root -g root ${CARGO_TARGET_DIR:-target}/release/paranoid-{boot,rt} /sbin
```

Currently, for configuration you have to enable Linux IMA subsystem manually by adding the following kernel parameters:
```
ima=on ima_policy=tcb ima_template=ima-ng
```
For example,
```bash
# Edit Grub bootloader configuration and add kernel parameters to GRUB_CMD_LINE_LINUX variable
sudo vi /etc/default/grub
sudo update-grub
```

### Server

Use above methods to download, install or compile `paranoid-srv` program and make it available in `PATH`. No additional dependencies or TPM hardware required for server to work properly.

# Usage

### Client

To attest system launch integrity, `paranoid-boot` must build list of known system states (integrity baselines). But first, TPM keys must be generated with `enroll` action:
```bash
sudo paranoid-boot enroll
```

Then current system state can be added to list of known integrity baselines with `fix` action:
```bash
sudo paranoid-boot fix
```

Your system can have multiple valid states depending on number of factors so every system state must be recorded and it could require *executing `paranoid-boot fix` a few times after system reboots until first successful attestation*. Also, it is required to launch `paranoid-boot fix` after every system update. In the future, this will be automated.

By default, only local attestation is performed, without involvement of remote attestation server. To use remote attestation, `--attest-remote` parameter must be provided and preliminary enrollment in attestation server is required. It can be done with `enroll` action like this:

```bash
sudo paranoid-boot --attest-remote enroll
```

You can deploy own attestation server using `paranoid-srv` binary, but by default open and free [counterinsider.dev]() is used.

You can see full list of `paranoid-boot` supported parameters, print help message with `paranoid-boot --help`:

```
paranoid-boot - system launch integrity measurement with TPM and Linux IMA

Program runs on every system startup and asserts boot integrity against previously established baselines

Usage: paranoid-boot [OPTIONS] [COMMAND]

Commands:
  configure  Configure system - enable IMA, install systemd service
  enroll     Generate TPM attestation key and enroll in attestation server
  fix        Establish new integrity baseline using current TPM PCR values and UEFI, IMA logs
  attest     Assert system launch integrity against previously established integrity baselines
  cleanup    Cleanup data directory, resetting enrollment state and removing attestation key
  help       Print this message or the help of the given subcommand(s)

Options:
  -d, --data-dir <DATA_DIR>
          Data directory
          
          [default: /var/lib/paranoid-system/client/boot]

      --seal-glob <SEAL_GLOB>
          Additional files for measurement as list of glob patterns
          
          Integrity of these files will be measured and included in boot integrity baseline

      --pcr-selection <PCR_SELECTION>
          Asserted TPM PCR (Platform Configuration Register) set
          
          [default: sha256:0,1,2,3,4,5,6,7]

      --attest-remote
          Enable remote attestation

      --server-url <SERVER_URL>
          Remote attestation server URL
          
          [default: https://counterinsider.dev]

      --server-cert-fingerprint <SERVER_CERT_FINGERPRINT>
          Remote attestation server TLS certificate fingerprint
          
          Calculated as `openssl s_client -connect <host>:<port> </dev/null 2>/dev/null | openssl x509 -fingerprint -noout -in /dev/stdin` Example: SHA1 Fingerprint=41:97:CB:04:97:77:C5:B5:A8:E4:0B:89:2F:46:49:28:96:0C:78:13

      --server-insecure
          Do not verify server TLS certificate
          
          Implied if `server_cert_fingerprint` is given

      --secured-payloads <SECURED_PAYLOADS>
          Secured payloads
          
          These files will be secured by server and returned only when attestation passed. The payloads are uploaded only once, when integrity baseline had been established (with `paranoid-boot fix` action). The payloads are encrypted with key stored in TPM before sending to the server and decrypted when downloaded. Note again that for updating payloads new enrollment required. Ensure that the files are accessible by the `user` (see --user option) and have unique names. After upload, the files can be manually deleted. When downloaded, the files are stored in `/run/tss/secured-payloads` folder.

      --secured-payloads-psk <SECURED_PAYLOADS_PSK>
          Use secured payloads encryption passphrase instead key stored in TPM.
          
          Payloads will be encrypted with the passphrase.

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version

Common options:
  -c, --config-file <CONFIG_FILE>
          Path to TOML configuration file
          
          The file contains corresponding to listed options.
          
          [default: /etc/paranoid-system/config.toml]

  -u, --user <USER>
          Drop privileges to this user
          
          [default: tss]

      --log-dir <LOG_DIR>
          Log location
          
          [default: /var/log/paranoid-system]

      --log-level <LOG_LEVEL>
          Logging level
          
          [default: info]
          [possible values: trace, debug, info, warn, error]

      --log-rotate-size <LOG_ROTATE_SIZE>
          Rotate logs as files with specified size in bytes
          
          [default: 8388608]

      --log-rotate-limit <LOG_ROTATE_LIMIT>
          Rotate logs with specified maximum number of files
          
          [default: 16]

      --max-system-states <MAX_SYSTEM_STATES>
          Maximum system states
          
          [default: 5]

      --no-https
          Do not use HTTPS. Plain text connection might expose UEFI logs to MiTM
```

To perform client integrity attestation, `paranoid-boot` must be launched on system startup with the very same parameters:

```bash
sudo paranoid-boot [<parameters-used>] attest
```

Or configuration in `/etc/paranoid-system/config.toml` file can be provided.

### Server

Server can be launched out of the box, generating necessary TLS certificate and secrets. You can replace it later in `/var/lib/paranoid-system/server/certs`.
If you bind server listener to higher port, no root privileges required. Just launch the program.

```bash
paranoid-srv --port 1443 --user <user>
```

To see full list of supported `paranoid-srv` parameters, print help message `paranoid-srv --help`:

```
paranoid-srv - attestation server checking client system integrity, including TPM quotes.

HTTP server with TLS support which asserts client system integrity against previously established baselines.

Usage: paranoid-srv [OPTIONS] [COMMAND]

Commands:
  serve    
  cleanup  
  help     Print this message or the help of the given subcommand(s)

Options:
  -d, --data-dir <DATA_DIR>
          Data directory
          
          [default: /var/lib/paranoid-system/server]

  -a, --address <ADDRESS>
          Listen to address
          
          [default: 0.0.0.0]

  -p, --port <PORT>
          Listen on port
          
          [default: 443]

      --tls-certfile <TLS_CERTFILE>
          Server TLS certificate path
          
          [default: <data_dir>/certs/server.cert]

      --tls-keyfile <TLS_KEYFILE>
          Server TLS private key path
          
          [default: <data_dir>/certs/server-privkey.pem]

      --disallow-enroll
          Disallow client enrollment
          
          If this option is given, new clients could not be added

      --totp-auth
          Enable RFC 6238 Time-Based One-Time Password (TOTP) authentication
          
          If enabled, client will be required to provide TOTP during baseline insertion and secured payload download

      --max-client-payloads <MAX_CLIENT_PAYLOADS>
          Maximum payloads client can upload to the server
          
          [default: 32]

      --max-payload-size <MAX_PAYLOAD_SIZE>
          Uploaded client payload size limit, bytes
          
          [default: 8192]

      --attestation-within <ATTESTATION_WITHIN>
          Maximum allowed duration for remote attestation to be completed, seconds
          
          [default: 300]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version

Common options:
  -c, --config-file <CONFIG_FILE>
          Path to TOML configuration file
          
          The file contains corresponding to listed options.
          
          [default: /etc/paranoid-system/config.toml]

  -u, --user <USER>
          Drop privileges to this user
          
          [default: tss]

      --log-dir <LOG_DIR>
          Log location
          
          [default: /var/log/paranoid-system]

      --log-level <LOG_LEVEL>
          Logging level
          
          [default: info]
          [possible values: trace, debug, info, warn, error]

      --log-rotate-size <LOG_ROTATE_SIZE>
          Rotate logs as files with specified size in bytes
          
          [default: 8388608]

      --log-rotate-limit <LOG_ROTATE_LIMIT>
          Rotate logs with specified maximum number of files
          
          [default: 16]

      --max-system-states <MAX_SYSTEM_STATES>
          Maximum system states
          
          [default: 5]

      --no-https
          Do not use HTTPS. Plain text connection might expose UEFI logs to MiTM
```

Configuration file can be provided or default `/etc/paranoid-system/config.toml` used.

### License

This code is open-source under MIT or Apache licensing. Contributions are very welcomed.



