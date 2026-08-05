import os
import requests

class LLMServiceError(Exception):
    pass

def generate_llm_response(prompt):
    ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")

    try:
        response = requests.post(
            f"{ollama_url}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
            },
            timeout=60,
        )

        response.raise_for_status()

    except requests.RequestException as error:
        raise LLMServiceError(f"Could not connect to Ollama: {error}") from error

    data = response.json()
    model_response = data.get("response")

    if not model_response:
        raise LLMServiceError("Ollama returned an empty response.")

    return model_response