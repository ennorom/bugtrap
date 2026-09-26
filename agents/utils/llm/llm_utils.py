import os

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline, BitsAndBytesConfig


def _load_bf16_model(model_id: str, cache_dir):
    return AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.bfloat16,
        max_position_embeddings=4096,
        device_map="auto",
        cache_dir=cache_dir,
        trust_remote_code=True,
    )


def _load_4bit_model(model_id: str, cache_dir):
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16,
    )
    return AutoModelForCausalLM.from_pretrained(
        model_id,
        quantization_config=bnb_config,
        device_map="auto",
        cache_dir=cache_dir,
        trust_remote_code=True,
    )

def get_model_and_tokenizer(model_id: str, cache_dir):
    torch.cuda.empty_cache()

    tokenizer = AutoTokenizer.from_pretrained(model_id, model_max_length=4096, truncation=True, trust_remote_code=True)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
        tokenizer.pad_token_id = tokenizer.eos_token_id
    tokenizer.padding_side="left"

    load_mode = os.getenv("KB_QWEN_LOAD_MODE", "4bit").strip().lower()
    if load_mode == "bf16":
        model = _load_bf16_model(model_id, cache_dir)
    else:
        try:
            model = _load_4bit_model(model_id, cache_dir)
        except Exception as exc:
            print(f"[WARN] 4-bit model load failed, falling back to bf16: {exc}")
            model = _load_bf16_model(model_id, cache_dir)

    return model, tokenizer

def get_pipe(model_id, cache_dir, temperature=0.1):
    if 'pipe' in locals():
        del pipe

    model, tokenizer = get_model_and_tokenizer(model_id, cache_dir)

    print("#"*50)
    print(f"Model Name: {model.config._name_or_path}")
    print("#"*50)

    return pipeline(
        "text-generation",
        model=model,
        tokenizer=tokenizer,
        pad_token_id=tokenizer.eos_token_id,
        truncation=True,
        max_new_tokens=512,
        temperature=temperature,
        do_sample=True,
        device_map="auto",
        use_cache=False
    )
