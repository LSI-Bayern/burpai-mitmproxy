# Burp AI Proxy

A proxy implementation for intercepting and proxying Burp AI requests to a
custom OpenAI-compatible backend. Portswigger does not enable use of company-
managed AI implementations, so this project attempts to resolve the issue by
modifying and proxying the requests to a OpenAI-compatible API backend that can
be managed by organizations themselves, and thus avoid sending sensitive data to
Portswigger and the US.

Currently working features are:

- Explain this
- API extensions use (Shadow Repeater has been tested)
- Repeater and Explore Issue

Currently missing features are:

- AI recorded login
- BAC false positive reduction

For now, tests are also incomplete.

See `Contributing` below for more information on how to contribute.

## Installation

- Clone the repo
- Install uv: https://docs.astral.sh/uv/getting-started/installation/

### (Optional) Build with PyInstaller

- `uv sync --group build`
- `uv run python -m PyInstaller burpai.spec --clean --noconfirm`

Environment variables:

- `LLM_URL`: Hardcode default LLM URL
- `ONEDIR`: Create a one-folder bundle instead of the default one-file bundle

## Running

- As simple as: `uv run burpai`
- Alternatively run it via the PyInstaller build

## Configuration

Configuration is stored in `~/.config/burpai/settings.json` (Linux) or
equivalent on other platforms. The main settings are prompted interactively. API
keys are saved in the system keyring unless specified via the command line.

On first run, Burp Suite Pro is automatically configured to:

- Enable AI feature
- Configure upstream proxy
- Install CA certificate

Managing configuration:

- View all options: `burpai --help`
- Edit settings file: `burpai --settings` (respects `$EDITOR`, otherwise uses
  common editors)
- Command-line arguments override `settings.json` (e.g.,
  `burpai --model qwen3-coder:30b`)

## Example: Ollama with extended context

Ollama's default context size is 2048 tokens. For larger contexts, either set
`OLLAMA_CONTEXT_LENGTH` or create a custom model
([Ollama FAQ](https://docs.ollama.com/faq#how-can-i-specify-the-context-window-size%3F)).

Example using a custom model:

```bash
ollama pull qwen3-coder:30b
ollama create qwen3-coder:30b-32k -f <(cat <<'EOF'
FROM qwen3-coder:30b
RENDERER qwen3-coder
PARSER qwen3-coder
PARAMETER num_ctx 32000
EOF
)
```

## Contributing

Currently only a subset of Burp's functionality has been implemented. I'm
hoping to receive PRs for additional request examples (see `doc/requests.md`) as
well as implementations for them.

For development, install dev dependencies: `uv sync --group dev`
