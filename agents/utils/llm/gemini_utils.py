# gemini_utils.py
import google.generativeai as genai
import json
import os

_client_initialized = False

def _init_client():
    global _client_initialized
    if not _client_initialized:
        genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))
        _client_initialized = True

def call_gemini_chat_completion(system_prompt: str, user_prompt: str,
                                model: str = "gemini-1.5-pro",
                                max_tokens: int = 2000) -> str:
    _init_client()
    model_obj = genai.GenerativeModel(model)
    prompt = system_prompt + "\n\n" + user_prompt
    resp = model_obj.generate_content(
        prompt,
        generation_config={"max_output_tokens": max_tokens}
    )
    return resp.text if resp and resp.text else ""
