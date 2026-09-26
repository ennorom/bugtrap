import time
import json
import copy
try:
	import tiktoken
except Exception:
	tiktoken = None
import openai
from openai import OpenAI
from pydantic import BaseModel
from types import SimpleNamespace


def get_tokens_from_string(text: str, open_ai_model: str):
	if tiktoken is None:
		# Fallback for environments without tokenizer dependency.
		return text.split()
	return tiktoken.encoding_for_model(open_ai_model).encode(text)
	# return tiktoken.get_encoding("cl100k_base").encode("tiktoken is great!")

def get_tokens_count_from_string(text: str, open_ai_model: str):
	return len(get_tokens_from_string(text, open_ai_model))

# def get_tokens_count_from_chat_messages(chat_messages: list, open_ai_model: str):
# 	text_prompt_list = get_prompt_texts_from_chat_templates([chat_messages])
# 	return get_tokens_count_from_string(text_prompt_list[0], open_ai_model)

def get_tokens_count_from_single_message(chat_message: str, open_ai_model: str):
	return get_tokens_count_from_string(chat_message, open_ai_model)


secs_per_unit = {"ms": 0.001, "s": 1, "m": 60, "h": 3600}

def convert_to_secs(str_time):
	if not str_time:
		return 0
	if "ms" in str_time:
		return float(str_time[:-2]) * secs_per_unit[str_time[-2:]]
	return float(str_time[:-1]) * secs_per_unit[str_time[-1:]]

def get_sleep_time(oai_headers, this_req_tokens: int):
	sleep_time = 0
	rem_req_time = convert_to_secs(oai_headers.get('x-ratelimit-reset-tokens'))
	rem_token_time = convert_to_secs(oai_headers.get('x-ratelimit-reset-requests'))
	rem_reqs = int(oai_headers.get('x-ratelimit-remaining-requests'))
	rem_toks = int(oai_headers.get('x-ratelimit-remaining-tokens'))

	if 1 > rem_reqs:
		sleep_time = rem_req_time
	if this_req_tokens > rem_toks:
		sleep_time = rem_token_time
	return sleep_time

def parse_oai_response(oai_res):
	oai_output = json.loads(oai_res.content)['choices'][0]['message']['content']
	# print(oai_output)
	try:
		oai_output = json.loads(oai_res.parse().choices[0].message.content, object_hook=lambda d: SimpleNamespace(**d))
	except Exception as err:
		print(err)
		content_json = json.loads(oai_res.content)['choices'][0]['message']['content']
		try:
			oai_output = json.loads(content_json, object_hook=lambda d: SimpleNamespace(**d))
		except Exception as err2:
			# print(f"Before {content_json}")
			if content_json[-1] == "\\":
				content_json += "n\"]}"
			else:
				if content_json[-2:] == "\"]":
					content_json += "}"
				else:
					content_json += "\"]}"
			# print(f"After {content_json}")
			try:
				oai_output = json.loads(content_json, object_hook=lambda d: SimpleNamespace(**d))
			except Exception as err3:
				print(f"Save Failed.")
	return oai_output


_client = None

def _get_client() -> OpenAI:
	global _client
	if _client is None:
		_client = OpenAI()
	return _client

def get_o_ai_response(messages: list, oai_model: str, max_new_tokens: int):
	client = _get_client()
	# return client.beta.chat.completions.parse(
	return client.beta.chat.completions.with_raw_response.parse(
		model=oai_model,
		messages=messages,
		max_completion_tokens=max_new_tokens,
		temperature=0.1
		# response_format={
		# 	'type': 'json_schema',
		# 	'json_schema': {
		# 		"name":"CodeGeneratorResponse", 
		# 		"schema": CodeGeneratorResponse.model_json_schema()
		# 	}
		# }
	)

def get_o_ai_response_with_one_retry(messages: list, oai_model: str, max_new_tokens: int):
	try:
		return get_o_ai_response(messages, oai_model, max_new_tokens)
	except openai.RateLimitError as e:
		print("A 429 status code was received; waiting 60s.")
		time.sleep(60)
		return get_o_ai_response(messages, oai_model, max_new_tokens)
	except openai.InternalServerError as e:
		print("An InternalServerError; waiting 5s before retrying.")
		time.sleep(5)
		return get_o_ai_response(messages, oai_model, max_new_tokens)


def call_chat_completion(system_prompt: str, user_prompt: str,
                         oai_model: str = "gpt-5.4", max_new_tokens: int = 1000) -> str:
	messages = [
		{"role": "system", "content": system_prompt},
		{"role": "user", "content": user_prompt},
	]
	res = get_o_ai_response_with_one_retry(messages, oai_model, max_new_tokens)
	try:
		return res.parse().choices[0].message.content
	except Exception:
		return json.loads(res.content)['choices'][0]['message']['content']
