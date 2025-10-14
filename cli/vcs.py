#!/usr/bin/env python3
# cli/vcs.py
# Production-ready CLI for NebulaCore control-plane (based on version 6).
# Features:
# - Robust HTTP session with retries/timeouts
# - Configurable base URL and API token via env or --base/--token
# - Commands: account_add, deploy, ai, agents, approvals, providers, provider_get
# - Support JSON payload files and pretty output
# - Clear error handling and exit codes

import os
import sys
import json
import click
import logging
import requests
from typing import Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Defaults / env
DEFAULT_BASE = os.getenv("NEB_CONTROL_URL", "http://localhost:8080").rstrip("/")
DEFAULT_API_PATH = "/api/v1"
DEFAULT_TIMEOUT = float(os.getenv("NEB_CLI_TIMEOUT", "10"))  # seconds
DEFAULT_RETRIES = int(os.getenv("NEB_CLI_RETRIES", "3"))
API_TOKEN_ENV = "NEB_API_TOKEN"

# Setup basic logging
logging.basicConfig(level=os.getenv("NEB_CLI_LOGLEVEL", "INFO"))

def build_session(timeout: float = DEFAULT_TIMEOUT, retries: int = DEFAULT_RETRIES, token: Optional[str] = None) -> requests.Session:
    s = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"]
    )
    s.mount("https://", HTTPAdapter(max_retries=retry_strategy))
    s.mount("http://", HTTPAdapter(max_retries=retry_strategy))
    s.request_timeout = timeout  # custom attr for convenience
    if token:
        s.headers.update({"Authorization": f"Bearer {token}"})
    s.headers.update({"Accept": "application/json"})
    return s

def api_url(base: str, path: str) -> str:
    return f"{base}{DEFAULT_API_PATH}{path}"

def pretty_print_resp(resp: requests.Response):
    try:
        j = resp.json()
        print(json.dumps(j, indent=2, ensure_ascii=False))
    except Exception:
        print(resp.text)

@click.group()
@click.option("--base", "-b", default=DEFAULT_BASE, help="Control-plane base URL (env NEB_CONTROL_URL)")
@click.option("--token", "-t", default=lambda: os.getenv(API_TOKEN_ENV, ""), help="API token (env NEB_API_TOKEN)")
@click.option("--timeout", default=DEFAULT_TIMEOUT, help="HTTP timeout (seconds)")
@click.option("--retries", default=DEFAULT_RETRIES, help="HTTP retries")
@click.pass_context
def cli(ctx, base, token, timeout, retries):
    """NebulaCore CLI (vcs) - production-ready"""
    ctx.ensure_object(dict)
    ctx.obj["BASE"] = base.rstrip("/")
    ctx.obj["TOKEN"] = token or None
    ctx.obj["TIMEOUT"] = float(timeout)
    ctx.obj["RETRIES"] = int(retries)
    ctx.obj["SESSION"] = build_session(timeout=ctx.obj["TIMEOUT"], retries=ctx.obj["RETRIES"], token=ctx.obj["TOKEN"])

# ---------------------------
# providers / accounts
# ---------------------------
@cli.command()
@click.option("--provider", "-p", required=True, help="Provider short name (e.g. aws,gcp,do)")
@click.option("--name", "-n", required=True, help="Account name")
@click.option("--config", "-c", default="{}", help="JSON string or @file.json with credentials/config")
@click.pass_context
def account_add(ctx, provider, name, config):
    """Add/link a provider account"""
    s: requests.Session = ctx.obj["SESSION"]
    base = ctx.obj["BASE"]
    try:
        cfg_obj = load_json_or_string(config)
    except Exception as e:
        click.echo(f"[error] invalid config JSON: {e}", err=True)
        sys.exit(2)
    payload = {"provider": provider, "name": name, "config": cfg_obj}
    url = api_url(base, "/providers")
    try:
        resp = s.post(url, json=payload, timeout=s.request_timeout)
        if not resp.ok:
            click.echo(f"[error] failed ({resp.status_code}):", err=True)
            pretty_print_resp(resp)
            sys.exit(3)
        pretty_print_resp(resp)
    except Exception as e:
        click.echo(f"[error] request failed: {e}", err=True)
        sys.exit(4)

@cli.command()
@click.pass_context
def providers(ctx):
    """List configured providers"""
    s: requests.Session = ctx.obj["SESSION"]
    base = ctx.obj["BASE"]
    url = api_url(base, "/providers")
    try:
        resp = s.get(url, timeout=s.request_timeout)
        if resp.ok:
            pretty_print_resp(resp)
        else:
            click.echo(f"[error] {resp.status_code}", err=True); pretty_print_resp(resp); sys.exit(3)
    except Exception as e:
        click.echo(f"[error] request failed: {e}", err=True); sys.exit(4)

@cli.command()
@click.argument("provider_id")
@click.pass_context
def provider_get(ctx, provider_id):
    """Get provider details by id/name"""
    s: requests.Session = ctx.obj["SESSION"]
    base = ctx.obj["BASE"]
    url = api_url(base, f"/providers/{provider_id}")
    try:
        resp = s.get(url, timeout=s.request_timeout)
        if resp.ok:
            pretty_print_resp(resp)
        else:
            click.echo(f"[error] {resp.status_code}", err=True); pretty_print_resp(resp); sys.exit(3)
    except Exception as e:
        click.echo(f"[error] request failed: {e}", err=True); sys.exit(4)

# ---------------------------
# deploy / jobs
# ---------------------------
@cli.command()
@click.option("--file", "-f", "file_path", help="Path to JSON job payload file (overrides other options)")
@click.option("--image", help="Image or artifact reference (string)")
@click.option("--type", "job_type", default="deploy", help="Job type")
@click.option("--priority", default=5, help="Priority")
@click.option("--payload", default="{}", help="JSON string payload")
@click.pass_context
def deploy(ctx, file_path, image, job_type, priority, payload):
    """Create a deploy job (POST /jobs). Provide --file @job.json or --payload JSON."""
    s: requests.Session = ctx.obj["SESSION"]
    base = ctx.obj["BASE"]
    payload_obj = {}
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                payload_obj = json.load(fh)
        except Exception as e:
            click.echo(f"[error] failed to read file: {e}", err=True); sys.exit(2)
    else:
        try:
            payload_obj = json.loads(payload)
        except Exception as e:
            click.echo(f"[error] invalid payload JSON: {e}", err=True); sys.exit(2)

    job = {"type": job_type, "priority": priority, "payload": payload_obj}
    if image:
        job["payload"].update({"image": image})
    url = api_url(base, "/jobs")
    try:
        resp = s.post(url, json=job, timeout=s.request_timeout)
        if resp.ok:
            pretty_print_resp(resp)
        else:
            click.echo(f"[error] {resp.status_code}", err=True); pretty_print_resp(resp); sys.exit(3)
    except Exception as e:
        click.echo(f"[error] request failed: {e}", err=True); sys.exit(4)

# ---------------------------
# AI assistant
# ---------------------------
@cli.command()
@click.argument("message")
@click.pass_context
def ai(ctx, message):
    """Send message to AI assistant"""
    s: requests.Session = ctx.obj["SESSION"]
    base = ctx.obj["BASE"]
    url = api_url(base, "/ai/chat")
    try:
        resp = s.post(url, json={"message": message}, timeout=s.request_timeout)
        if resp.ok:
            pretty_print_resp(resp)
        else:
            click.echo(f"[error] {resp.status_code}", err=True); pretty_print_resp(resp); sys.exit(3)
    except Exception as e:
        click.echo(f"[error] request failed: {e}", err=True); sys.exit(4)

# ---------------------------
# agents / approvals
# ---------------------------
@cli.command()
@click.pass_context
def agents(ctx):
    """List agents"""
    s: requests.Session = ctx.obj["SESSION"]
    base = ctx.obj["BASE"]
    url = api_url(base, "/agents")
    try:
        resp = s.get(url, timeout=s.request_timeout)
        if resp.ok:
            pretty_print_resp(resp)
        else:
            click.echo(f"[error] {resp.status_code}", err=True); pretty_print_resp(resp); sys.exit(3)
    except Exception as e:
        click.echo(f"[error] request failed: {e}", err=True); sys.exit(4)

@cli.command()
@click.pass_context
def approvals(ctx):
    """List pending approvals"""
    s: requests.Session = ctx.obj["SESSION"]
    base = ctx.obj["BASE"]
    url = api_url(base, "/approvals")
    try:
        resp = s.get(url, timeout=s.request_timeout)
        if resp.ok:
            pretty_print_resp(resp)
        else:
            click.echo(f"[error] {resp.status_code}", err=True); pretty_print_resp(resp); sys.exit(3)
    except Exception as e:
        click.echo(f"[error] request failed: {e}", err=True); sys.exit(4)

# ---------------------------
# Utilities
# ---------------------------
def load_json_or_string(value: str):
    """
    Accepts:
      - JSON string: '{"a":1}'
      - File reference: @./file.json
    Returns parsed JSON (dict/list).
    """
    if not value:
        return {}
    if value.startswith("@"):
        path = value[1:]
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    # try parse JSON string
    return json.loads(value)

# Entry point
if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\nInterrupted", err=True)
        sys.exit(130)
```0

