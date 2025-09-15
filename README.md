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

### 3) Set your OpenAI API key

Mac/Linux:

```bash
export OPENAI_API_KEY="sk-..."
```

Windows (PowerShell):

```powershell
$env:OPENAI_API_KEY = "sk-..."
```

The code uses the `OPENAI_API_KEY` environment variable (see `src/core.py`).

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

## Run the Streamlit app

```bash
streamlit run src/streamlit.py
```

In the app:
- Provide your OpenAI API key in the sidebar (or set `OPENAI_API_KEY` beforehand).
- Enter a prompt describing the system or network flow.
- Optionally upload supporting files (text/code/images) to ground the model.
- Click “Generate Diagram” to produce editable Mermaid text.
