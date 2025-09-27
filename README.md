# auto-diagram
Automatic diagram generation with GenAI

## Setup

### 1) Create and activate a virtual environment

Mac/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

Windows (PowerShell):

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

### 2) Install dependencies

```bash
pip install -r requirements.txt
```

### 3) Set your API keys (Optional for streamlit app)

Mac/Linux:

```bash
export OPENAI_API_KEY="sk-..."      # Required for OpenAI
export GEMINI_API_KEY="..."         # Optional: set if using Gemini
```

Windows (PowerShell):

```powershell
$env:OPENAI_API_KEY = "sk-..."
$env:GEMINI_API_KEY = "..."
```

The code uses these environment variables when calling providers (see `src/core.py`).

## Run the Streamlit app

```bash
streamlit run src/app.py
```

In the app:
- Provide your API keys in the sidebar (or set `OPENAI_API_KEY`/`GEMINI_API_KEY` environment variables beforehand).
- Enter a prompt describing the system or network flow.
- Optionally upload supporting files (text/code/images) to ground the model.
- Click “Generate Diagram” to produce editable Mermaid text.

Tabs:
- **Preview**: renders latest generated Mermaid diagram.
- **Editor**: adjust the Mermaid diagram source directly.
- **Export**:
  - **mermaid.live** - open editor in mermaid.live.
  - **draw.io** - view import steps to draw.io (diagrams.net).
  - **SVG** - download as .svg file.

## Run the Streamlit app with Docker

```bash
docker build -t auto-diagram .
docker run --rm \
  -p 8501:8501 \
  -e OPENAI_API_KEY=sk-... \
  -e GEMINI_API_KEY=... \
  -v path/to/local/dir:/data/auto-diagram \
  auto-diagram
```

- Replace the example API keys with your real credentials. Add or remove `-e` flags depending on the providers you use.
- The volume mapping to `/data/auto-diagram` makes chat state persistent across container restarts; omit it if you prefer ephemeral sessions.
- Open http://localhost:8501 in your browser to use the containerized app.

## Run the CLI

You can run the CLI script directly. The `--supporting-files` option points to a directory whose files are added to context. An example context is provided under `examples/NSCacheFlush/context`.

```bash
# From the repo root
python src/cli.py create \
  "Generate a Mermaid diagram explaining the NSCacheFlush network flow" \
  --supporting-files examples/NSCacheFlush/context \
  --output output/diagram.mmd
```

The diagram text (Mermaid) is saved to `output/diagram.mmd`.
