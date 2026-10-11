# secproxy

Secproxy is an egress proxy that lets a program running in a sandbox (say, a coding agent) use secrets without them ever being stored or materialized in the sandbox.

⚠️ This project is vibecoded. ⚠️ It is a proof of concept. No guarantees are made regarding its security or correctness. Please evaluate it yourself before using for anything important.

## How it Works

The sandbox gets placeholders like `sp_github_k7f3m9q2…` instead of real tokens. When it sends a placeholder to an allowed host, in the declared header, with an allowed method and path, secproxy swaps in the real value and forwards the request. Anything else is refused with a message saying why. Hosts with no secret can be passed through untouched; everything else is denied.

It is not a sandbox: it only helps if the sandbox has no other route to the internet.

## Install

```
go install github.com/taylorai/secproxy/cmd/secproxy@latest
```

Linux binaries from a checkout: `make linux` (writes `dist/`). The `Dockerfile` builds a distroless image.

## Quickstart (laptop)

1. Write a config, e.g. `~/.config/secproxy/laptop.yaml`:

```yaml
version: 1
listen: { connect: "127.0.0.1:8080" }        # for `serve`; `run` picks its own port
ca: { persist_dir: ~/.config/secproxy/ca }   # one CA, reused across restarts
unmatched_host: deny

egress: [pypi.org, files.pythonhosted.org]   # passed through, no secrets

secrets:
  github: { from_env: SP_GITHUB_TOKEN, env: GITHUB_TOKEN }

bindings:
  - secret: github
    hosts: [api.github.com]
    slot: { header: Authorization, format: "Bearer {secret}" }
    methods: [GET, POST, PATCH]
    paths: ["/repos/my-org/**"]
```

2. Check it:

```
secproxy check --config ~/.config/secproxy/laptop.yaml
```

3. Run a command behind the proxy. Its environment gets the placeholder, the proxy variables and the CA certificate paths; the real token stays in the proxy:

```
SP_GITHUB_TOKEN=ghp_… secproxy run --config ~/.config/secproxy/laptop.yaml -- gh api /repos/my-org/tool
```

On macOS, Go programs such as `gh` read the keychain rather than `SSL_CERT_FILE`, so trust the CA once:

```
security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db ~/.config/secproxy/ca/ca.pem
```

For a sidecar, run `secproxy serve` with `listen.transparent: ":443"` behind a relay that sends all of the sandbox's HTTPS to it, or `listen.connect: ":8080"` for programs that honour `HTTPS_PROXY`. A full annotated config is in [examples/secproxy.yaml](examples/secproxy.yaml).

## Commands

```
secproxy check --config cfg.yaml            validate and print the effective policy
secproxy serve --config cfg.yaml            run the proxy
secproxy env   --config cfg.yaml            print the env the sandbox should get
secproxy run   --config cfg.yaml -- cmd …   proxy on loopback, run cmd with that env
```

Every decision is one JSON line on stdout. Secrets, placeholders, header values, query strings and bodies are never logged.

## Development

```
sfw uv sync                                                      # dev tools (prek) into .venv
.venv/bin/prek install --hook-type pre-commit --hook-type pre-push
make test                                                        # go vet + go test -race
```

Hooks run gofmt, go vet, the tests and gitleaks.

## License

Apache 2.0. Borrowed designs and code are credited in [NOTICE](NOTICE).
