import time
import json
import os

try:
	import anthropic
except Exception:
	anthropic = None


# # # # # # # # # # # #
#    Token Counters   #
# # # # # # # # # # # #

def get_tokens_count_from_string(text: str, model: str) -> int:
	"""Estimate token count for a string.

	Uses the Anthropic SDK's token counter when available, otherwise falls
	back to a character-based approximation (~4 chars per token).
	"""
	client = _get_client()
	try:
		result = client.messages.count_tokens(
			model=model,
			messages=[{"role": "user", "content": text}],
		)
		return result.input_tokens
	except Exception:
		return max(1, len(text) // 4)

def get_tokens_count_from_single_message(chat_message: str, model: str) -> int:
	return get_tokens_count_from_string(chat_message, model)


# # # # # # # # # # # #
#    Time Counters    #
# # # # # # # # # # # #

secs_per_unit = {"ms": 0.001, "s": 1, "m": 60, "h": 3600}

def convert_to_secs(str_time) -> float:
	if not str_time:
		return 0
	str_time = str(str_time).strip()
	if "ms" in str_time:
		return float(str_time[:-2]) * secs_per_unit["ms"]
	if str_time and str_time[-1] in secs_per_unit:
		return float(str_time[:-1]) * secs_per_unit[str_time[-1]]
	return 0

def get_sleep_time(headers, this_req_tokens: int) -> float:
	"""Compute how long to sleep based on Anthropic rate-limit response headers.

	Anthropic exposes:
	  anthropic-ratelimit-requests-remaining
	  anthropic-ratelimit-tokens-remaining
	  anthropic-ratelimit-requests-reset   (ISO-8601 or seconds string)
	  anthropic-ratelimit-tokens-reset     (ISO-8601 or seconds string)
	"""
	sleep_time = 0.0
	try:
		rem_reqs = int(headers.get("anthropic-ratelimit-requests-remaining", 1))
		rem_toks = int(headers.get("anthropic-ratelimit-tokens-remaining", this_req_tokens + 1))
		req_reset = convert_to_secs(headers.get("anthropic-ratelimit-requests-reset", "0s"))
		tok_reset = convert_to_secs(headers.get("anthropic-ratelimit-tokens-reset", "0s"))

		if rem_reqs < 1:
			sleep_time = req_reset
		if this_req_tokens > rem_toks:
			sleep_time = max(sleep_time, tok_reset)
	except Exception:
		pass
	return sleep_time


# # # # # # # # # # # # #
#   Anthropic Helpers   #
# # # # # # # # # # # # #

_client = None

def _get_client():
	global _client
	if _client is None:
		if anthropic is None:
			raise RuntimeError(
				"anthropic package is not installed. Run: pip install anthropic"
			)
		_client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
	return _client


def get_claude_response(messages: list, model: str, max_new_tokens: int,
                        system_prompt: str = ""):
	"""Send a request to the Anthropic Messages API and return the raw response object."""
	client = _get_client()
	kwargs = dict(
		model=model,
		max_tokens=max_new_tokens,
		messages=messages,
		temperature=0.1,
	)
	if system_prompt:
		kwargs["system"] = system_prompt
	return client.messages.create(**kwargs)


def get_claude_response_with_one_retry(messages: list, model: str,
                                       max_new_tokens: int,
                                       system_prompt: str = ""):
	"""Attempt the API call once, retrying once on rate-limit or server errors."""
	try:
		return get_claude_response(messages, model, max_new_tokens, system_prompt)
	except anthropic.RateLimitError:
		print("A 429 rate-limit error was received; waiting 60s.")
		time.sleep(60)
		return get_claude_response(messages, model, max_new_tokens, system_prompt)
	except anthropic.InternalServerError:
		print("An InternalServerError was received; waiting 5s before retrying.")
		time.sleep(5)
		return get_claude_response(messages, model, max_new_tokens, system_prompt)
	except anthropic.APIConnectionError:
		print("A connection error was received; waiting 10s before retrying.")
		time.sleep(10)
		return get_claude_response(messages, model, max_new_tokens, system_prompt)


def parse_claude_response(response) -> str:
	"""Extract the text content from an Anthropic Messages response object."""
	try:
		parts = response.content
		if parts:
			return parts[0].text
	except Exception as err:
		print(f"parse_claude_response error: {err}")
	return ""


def call_chat_completion(system_prompt: str, user_prompt: str,
                         model: str = "claude-opus-4-6",
                         max_new_tokens: int = 1000) -> str:
	"""Drop-in equivalent of openai_utils.call_chat_completion.

	Returns the raw text content of the model's reply.
	"""
	messages = [{"role": "user", "content": user_prompt}]
	response = get_claude_response_with_one_retry(
		messages, model, max_new_tokens, system_prompt=system_prompt
	)
	return parse_claude_response(response)
