from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

MODEL_NAME = "microsoft/Phi-3.5-mini-instruct"

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=False)
model = AutoModelForCausalLM.from_pretrained(MODEL_NAME, trust_remote_code=False, device_map="auto")

print("Loaded model successfully!")
