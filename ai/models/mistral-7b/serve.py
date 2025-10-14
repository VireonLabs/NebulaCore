import os, shutil, subprocess, glob
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
import threading

MODEL_DIR = "./mistral-7b"
HF_TOKEN = os.environ.get("HF_TOKEN", "")
MODEL_NAME = "mistralai/Mistral-7B-v0.2"

app = FastAPI()
model = None
tokenizer = None

class ChatRequest(BaseModel):
    messages: list

def download_weights():
    if not HF_TOKEN:
        raise Exception("HF_TOKEN required!")
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR, exist_ok=True)
    if not glob.glob(f"{MODEL_DIR}/*.bin") and not glob.glob(f"{MODEL_DIR}/*.safetensors"):
        print("Downloading model weights from Hugging Face...")
        subprocess.run([
            "huggingface-cli", "download", MODEL_NAME,
            "--cache-dir", MODEL_DIR,
            "--token", HF_TOKEN,
            "--resume"
        ], check=True)
    print("Model weights ready.")

def load_model():
    global model, tokenizer
    download_weights()
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForCausalLM.from_pretrained(MODEL_DIR)

@app.on_event("startup")
def startup_event():
    threading.Thread(target=load_model).start()

@app.post("/v1/chat")
def chat(req: ChatRequest):
    global model, tokenizer
    if model is None or tokenizer is None:
        raise HTTPException(503, detail="Model loading, please wait...")
    pipe = pipeline("text-generation", model=model, tokenizer=tokenizer, device=0)
    prompt = "\n".join([msg["content"] for msg in req.messages])
    out = pipe(prompt, max_new_tokens=128)[0]["generated_text"]
    return {"reply": out}