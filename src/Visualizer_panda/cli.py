# src/my_package/cli.py
import typer
import core
from typing import Optional

app = typer.Typer()


@app.command()
def create(
    prompt: str, supporting_files: Optional[str] = None, output: str = "mermaid.txt"
):
    """
    Process data for a user from the command line.
    """
    print(f"CLI: Starting process for {prompt} - {supporting_files} - {output}")
    core.create_diagram(
        prompt=prompt, supporting_files_dir=supporting_files, output_path=output
    )
    print("CLI: ✅ Process complete!")


if __name__ == "__main__":
    app()
