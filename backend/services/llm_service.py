import os

import requests


class LLMServiceError(Exception):
    pass


def generate_llm_response(prompt):
    ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
    debug_llm = os.getenv("DEBUG_LLM", "false").lower() == "true"

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1,
        },
    }

    if debug_llm:
        print("\n===== PROMPT SENT TO OLLAMA =====")
        print(prompt)

    try:
        response = requests.post(
            f"{ollama_url}/api/generate",
            json=payload,
            timeout=120,
        )

        if debug_llm:
            print("\n===== OLLAMA HTTP STATUS =====")
            print(response.status_code)
            print("\n===== RAW OLLAMA HTTP BODY =====")
            print(response.text)

        response.raise_for_status()

    except requests.RequestException as error:
        raise LLMServiceError(f"Ollama request failed: {error}") from error

    data = response.json()
    model_response = data.get("response")

    if debug_llm:
        print("\n===== RAW MODEL RESPONSE TEXT =====")
        print(model_response)

    if not model_response:
        raise LLMServiceError("Ollama returned an empty response.")

    return model_response