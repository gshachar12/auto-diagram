import tiktoken


def count_tokens(text: str):
    encoding = tiktoken.encoding_for_model("gpt-5-")
    return len(encoding.encode(text))
