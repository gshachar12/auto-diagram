import json
import re

def clean_and_load_json(json_str):
    """
    Cleans common small mistakes in JSON strings and returns a Python object.
    Returns an empty list [] if the string is empty to avoid 'Char 0' errors.
    """
    if not json_str or not json_str.strip():
        return []

    # 1. Remove Markdown code blocks if the LLM included them
    # (e.g., ```json ... ```)
    json_str = re.sub(r'^```json\s*|```$', '', json_str.strip(), flags=re.MULTILINE)

    # 2. Fix trailing commas in lists or objects: [1, 2,] -> [1, 2]
    # This is the most common 'small mistake'
    json_str = re.sub(r',\s*([\]}])', r'\1', json_str)

    # 3. Convert single quotes to double quotes (if they aren't inside words)
    # Note: This is a 'best-effort' regex; it's safer to prompt the LLM for double quotes.
    json_str = re.sub(r"'(?=\s*[\{\}\[\]\:])|(?<=[\{\}\[\]\:]\s*)'", '"', json_str)

    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        # If it still fails, we log the error instead of crashing the app
        print(f"Failed to repair JSON: {e}")
        return []

# Example usage with your ChatSession
# entities = clean_and_load_json(st.session_state.chat.entities_json)