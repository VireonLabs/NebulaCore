// web/src/App.jsx
// Production-grade NebulaCore Dashboard (shadcn/ui + advanced features)
// - Uses shadcn/ui components (assumes project has them under "@/components/ui/*")
// - WebAuthn unlock with PIN fallback
// - AI chat with streaming (Fetch stream + SSE fallback) + retry/backoff
// - Local caching of chat + optimistic UI + rate-limit + typing indicator
// - i18n (react-i18next lightweight init), markdown rendering, auto-scroll
// - Small performance & resilience improvements (debounce, reconnect, graceful failures)

import React, { useCallback, useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { motion } from "framer-motion";
import create from "zustand";
import i18n from "i18next";
import { initReactI18next, useTranslation } from "react-i18next";
import ReactMarkdown from "react-markdown";

// -------------------------
// i18n (lightweight)
// -------------------------
i18n.use(initReactI18next).init({
  fallbackLng: "en",
  resources: {
    en: {
      translation: {
        title: "NebulaCore Dashboard",
        subtitle: "Distributed infra control",
        agents: "Agents",
        providers: "Providers",
        jobs: "Jobs",
        aiAssistant: "AI Assistant",
        typeMessage: "Type a message...",
        send: "Send",
        refresh: "Refresh",
        unlock: "Unlock",
        biometricPrompt: "Please authenticate (WebAuthn or PIN)",
        devBypass: "DEV BYPASS",
      },
    },
    ar: {
      translation: {
        title: "لوحة NebulaCore",
        subtitle: "إدارة البنية التحتية الموزعة",
        agents: "الوكلاء",
        providers: "المزودون",
        jobs: "المهام",
        aiAssistant: "مساعد الذكاء الاصطناعي",
        typeMessage: "اكتب رسالة...",
        send: "أرسل",
        refresh: "تحديث",
        unlock: "تحقق",
        biometricPrompt: "يرجى التحقق (WebAuthn أو PIN)",
        devBypass: "تجاوز التطوير",
      },
    },
  },
});

// -------------------------
// Zustand store (compact)
// -------------------------
const useStore = create((set) => ({
  aiMode: Number(localStorage.getItem("aiMode") || 0), // 0=Proxy,1=Direct,2=Disabled
  setAIMode: (mode) => {
    localStorage.setItem("aiMode", String(mode));
    set(() => ({ aiMode: mode }));
    // best-effort sync
    fetch("/api/v1/ai/mode", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode }) }).catch(() => {});
  },
  summary: { agents: 0, providers: 0, jobs: 0 },
  setSummary: (s) => set(() => ({ summary: s })),
}));

// -------------------------
// Utilities: WebAuthn helpers
// -------------------------
async function getWebAuthnChallenge() {
  const res = await fetch("/api/v1/auth/webauthn/challenge");
  if (!res.ok) throw new Error("Failed to get challenge");
  return res.json();
}
function base64UrlToBuffer(base64url) {
  const padding = "=".repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = window.atob(base64);
  const buf = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; ++i) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}
function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function webAuthnGetAssertion() {
  const challengeData = await getWebAuthnChallenge();
  const publicKey = { ...challengeData, challenge: base64UrlToBuffer(challengeData.challenge) };
  if (publicKey.allowCredentials) {
    publicKey.allowCredentials = publicKey.allowCredentials.map((c) => ({ ...c, id: base64UrlToBuffer(c.id) }));
  }
  const cred = await navigator.credentials.get({ publicKey });
  const auth = cred.response;
  return {
    id: cred.id,
    rawId: bufferToBase64Url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToBase64Url(auth.clientDataJSON),
      authenticatorData: bufferToBase64Url(auth.authenticatorData),
      signature: bufferToBase64Url(auth.signature),
      userHandle: auth.userHandle ? bufferToBase64Url(auth.userHandle) : null,
    },
  };
}

// -------------------------
// Small resilient helpers
// -------------------------
function clamp(v, a, b) {
  return Math.max(a, Math.min(b, v));
}
function sleep(ms) {
  return new Promise((res) => setTimeout(res, ms));
}

// -------------------------
// Chat storage / caching
// -------------------------
const CHAT_CACHE_KEY = "nebula_chat_v1";
function loadCachedChat() {
  try {
    const raw = localStorage.getItem(CHAT_CACHE_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch {
    return [];
  }
}
function saveCachedChat(chat) {
  try {
    localStorage.setItem(CHAT_CACHE_KEY, JSON.stringify(chat.slice(-200))); // keep last 200 messages
  } catch {}
}

// -------------------------
// Main App
// -------------------------
export default function App() {
  const { t, i18n } = useTranslation();
  const storeSummary = useStore((s) => s.summary);
  const setSummary = useStore((s) => s.setSummary);
  const aiMode = useStore((s) => s.aiMode);
  const setAIMode = useStore((s) => s.setAIMode);

  const [chat, setChat] = useState(loadCachedChat());
  const [msg, setMsg] = useState("");
  const [sending, setSending] = useState(false);
  const [typing, setTyping] = useState(false);
  const [unlocked, setUnlocked] = useState(Boolean(localStorage.getItem("jwt")));
  const [error, setError] = useState(null);
  const [lastSendAt, setLastSendAt] = useState(0);
  const chatRef = useRef(null);

  useEffect(() => {
    if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight;
    saveCachedChat(chat);
  }, [chat]);

  useEffect(() => {
    // initial summary fetch and light WebAuthn probe (non-blocking)
    fetchSummary().catch(() => {});
    (async () => {
      try {
        const probe = await fetch("/api/v1/auth/webauthn/challenge").catch(() => null);
        if (probe && probe.ok) {
          // server supports WebAuthn
        }
      } catch {}
    })();
    // eslint-disable-next-line
  }, []);

  const fetchSummary = useCallback(async () => {
    try {
      const [agents, providers, jobs] = await Promise.all([
        fetch("/api/v1/agents").then((r) => (r.ok ? r.json() : [])).catch(() => []),
        fetch("/api/v1/providers").then((r) => (r.ok ? r.json() : [])).catch(() => []),
        fetch("/api/v1/jobs").then((r) => (r.ok ? r.json() : [])).catch(() => []),
      ]);
      setSummary({ agents: agents.length || 0, providers: providers.length || 0, jobs: jobs.length || 0 });
    } catch (e) {
      // tolerate
    }
  }, [setSummary]);

  async function performWebAuthnUnlock() {
    try {
      const assertion = await webAuthnGetAssertion();
      const res = await fetch("/api/v1/auth/webauthn/verify", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(assertion) });
      if (!res.ok) throw new Error("verify failed");
      const data = await res.json();
      if (data && data.token) localStorage.setItem("jwt", data.token);
      setUnlocked(true);
      return true;
    } catch (e) {
      const pin = window.prompt("Biometric unavailable — enter device PIN (dev fallback)");
      if (pin) {
        try {
          const r = await fetch("/api/v1/auth/pin", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ pin }) });
          if (r.ok) {
            const data = await r.json();
            if (data.token) localStorage.setItem("jwt", data.token);
            setUnlocked(true);
            return true;
          }
        } catch {}
      }
      alert("Unlock failed");
      return false;
    }
  }

  // -------------------------
  // Streaming + SSE send with robust fallback + backoff
  // -------------------------
  async function sendWithResilience(message) {
    // rate-limit: 300ms min between sends
    const now = Date.now();
    if (now - lastSendAt < 300) {
      return; // ignore rapid repeats
    }
    setLastSendAt(now);

    setSending(true);
    setTyping(true);
    setError(null);

    // optimistic UI
    setChat((c) => {
      const next = [...c, { by: "user", text: message, ts: Date.now() }];
      saveCachedChat(next);
      return next;
    });

    const token = localStorage.getItem("jwt");
    const headers = { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) };
    // try streaming endpoint first w/ exponential backoff on transient failures
    let attempts = 0;
    const maxAttempts = 3;
    let usedStreaming = false;

    while (attempts < maxAttempts) {
      attempts++;
      try {
        const controller = new AbortController();
        const timeoutMs = 2 * 60 * 1000; // 2 min per attempt
        const timeout = setTimeout(() => controller.abort(), timeoutMs);

        const res = await fetch("/api/v1/ai/chat/stream", {
          method: "POST",
          headers,
          body: JSON.stringify({ message, mode: aiMode }),
          signal: controller.signal,
          cache: "no-store",
        });

        clearTimeout(timeout);

        if (!res.ok) throw new Error("streaming-not-available");

        // Read stream body as text chunks
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let accumulated = "";
        // append placeholder AI message
        setChat((c) => {
          const next = [...c, { by: "ai", text: "", ts: Date.now() }];
          saveCachedChat(next);
          return next;
        });
        usedStreaming = true;
        let aiIndex = null;

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = dec.decode(value, { stream: true });
          accumulated += chunk;
          // update last AI message
          setChat((c) => {
            // find last AI message index (heuristic)
            let idx = -1;
            for (let i = c.length - 1; i >= 0; i--) {
              if (c[i].by === "ai") {
                idx = i;
                break;
              }
            }
            if (idx === -1) {
              // fallback: append
              return [...c, { by: "ai", text: chunk, ts: Date.now() }];
            }
            const copy = c.slice();
            copy[idx] = { ...copy[idx], text: (copy[idx].text || "") + chunk };
            saveCachedChat(copy);
            return copy;
          });
        }

        // streaming finished successfully
        setTyping(false);
        setSending(false);
        fetchSummary().catch(() => {});
        return;
      } catch (err) {
        // streaming attempt failed -> try SSE fallback (if supported) or plain POST fallback
        console.warn("streaming attempt failed:", err);
        // short backoff
        const backoff = clamp(500 * Math.pow(2, attempts - 1), 500, 5000);
        await sleep(backoff);
      }
    }

    // If streaming entirely failed, try SSE connect as alternative (server might support text/event-stream)
    try {
      const sseSupported = await trySSE(message, headers);
      if (sseSupported) {
        setTyping(false);
        setSending(false);
        fetchSummary().catch(() => {});
        return;
      }
    } catch (e) {
      // continue to final fallback
    }

    // final fallback: simple POST /ai/chat
    try {
      const r = await fetch("/api/v1/ai/chat", { method: "POST", headers, body: JSON.stringify({ message, mode: aiMode }) });
      if (!r.ok) {
        const txt = await r.text();
        setChat((c) => [...c, { by: "ai", text: `Error: ${r.status} ${txt}`, ts: Date.now() }]);
      } else {
        const data = await r.json();
        const reply = data.reply || data.output || JSON.stringify(data);
        setChat((c) => [...c, { by: "ai", text: reply, ts: Date.now() }]);
      }
    } catch (e) {
      setChat((c) => [...c, { by: "ai", text: "Network/error contacting server", ts: Date.now() }]);
    } finally {
      setTyping(false);
      setSending(false);
      fetchSummary().catch(() => {});
    }
  }

  // Try an SSE endpoint: POST to /api/v1/ai/chat/sse then listen to the returned EventSource URL OR open /api/v1/ai/chat/sse?msg=...
  // Many servers instead accept GET with query params; here we try POST then fallback to GET-based SSE.
  async function trySSE(message, headers) {
    try {
      // Preferred: server returns a URL to connect SSE to handle multiple clients
      const init = await fetch("/api/v1/ai/chat/sse/init", { method: "POST", headers, body: JSON.stringify({ message, mode: aiMode }) }).catch(() => null);
      let sseUrl = null;
      if (init && init.ok) {
        const j = await init.json().catch(() => null);
        sseUrl = j?.url || null;
      }
      if (!sseUrl) {
        // fallback: server may accept GET /api/v1/ai/chat/sse?message=...
        // encode small messages only
        const qs = new URLSearchParams({ message: message.slice(0, 2000), mode: String(aiMode) }).toString();
        sseUrl = `/api/v1/ai/chat/sse?${qs}`;
      }

      return await new Promise((resolve, reject) => {
        const es = new EventSource(sseUrl);
        let receivedAny = false;
        // optimistic insertion: append empty ai message
        setChat((c) => [...c, { by: "ai", text: "", ts: Date.now() }]);
        es.onmessage = (ev) => {
          receivedAny = true;
          const data = ev.data;
          setChat((c) => {
            const copy = c.slice();
            // update last ai item
            let idx = -1;
            for (let i = c.length - 1; i >= 0; i--) if (c[i].by === "ai") { idx = i; break; }
            if (idx === -1) return [...c, { by: "ai", text: data }];
            copy[idx] = { ...copy[idx], text: (copy[idx].text || "") + data };
            saveCachedChat(copy);
            return copy;
          });
        };
        es.onerror = (err) => {
          es.close();
          if (!receivedAny) return reject(new Error("SSE failed"));
          resolve(true);
        };
        es.onopen = () => {
          // connected
        };
        // automatic timeout
        setTimeout(() => {
          es.close();
          resolve(true);
        }, 120000);
      });
    } catch (e) {
      return false;
    }
  }

  function handleSend() {
    if (!msg || sending) return;
    sendWithResilience(msg);
    setMsg("");
}
  
  // quick util to clear chat (with user confirmation)
  function clearChat() {
    if (!confirm("Clear chat history?")) return;
    setChat([]);
    saveCachedChat([]);
  }

  return (
    <div className="max-w-6xl mx-auto p-6">
      <header className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold">{t("title")}</h1>
          <div className="text-sm text-slate-500">{t("subtitle")}</div>
        </div>
        <div className="flex items-center gap-3">
          <Select value={i18n.language} onValueChange={(v) => i18n.changeLanguage(v)}>
            <SelectTrigger className="w-28">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="ar">العربية</SelectItem>
              <SelectItem value="en">English</SelectItem>
            </SelectContent>
          </Select>
          <div className="text-sm">AI Mode: {aiMode === 0 ? "Proxy" : aiMode === 1 ? "Direct" : "Disabled"}</div>
        </div>
      </header>

      {!unlocked ? (
        <div className="max-w-3xl mx-auto">
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="bg-white p-6 rounded shadow">
            <h2 className="text-lg font-semibold">{t("unlock")}</h2>
            <p className="text-sm text-slate-600">{t("biometricPrompt")}</p>
            <div className="mt-4 flex gap-3">
              <Button onClick={performWebAuthnUnlock}>{t("unlock")}</Button>
              <Button variant="ghost" onClick={() => { if (confirm("Bypass auth (dev)?")) setUnlocked(true); }}>{t("devBypass")}</Button>
            </div>
          </motion.div>
        </div>
      ) : (
        <div className="grid md:grid-cols-3 gap-4">
          <div className="col-span-1">
            <Card className="p-4">
              <CardContent>
                <div className="mb-2 font-semibold">AI Mode</div>
                <div className="flex flex-col gap-2">
                  <label className="flex items-center gap-2">
                    <input type="radio" name="aiMode" checked={aiMode === 0} onChange={() => { setAIMode(0); }} />
                    <span>Proxy</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input type="radio" name="aiMode" checked={aiMode === 1} onChange={() => { setAIMode(1); }} />
                    <span>Direct</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input type="radio" name="aiMode" checked={aiMode === 2} onChange={() => { setAIMode(2); }} />
                    <span>Disabled</span>
                  </label>
                </div>
                <div className="mt-4">
                  <Button variant="ghost" onClick={() => { fetchSummary(); }}>{t("refresh")}</Button>
                </div>
                <div className="mt-4 text-sm text-slate-600">
                  Quick actions: <button className="underline" onClick={() => clearChat()}>Clear Chat</button>
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="md:col-span-2 space-y-4">
            <div className="grid grid-cols-3 gap-3">
              <Card className="p-3">
                <div className="text-xs text-slate-500">{t("agents")}</div>
                <div className="text-2xl font-bold">{storeSummary.agents}</div>
              </Card>
              <Card className="p-3">
                <div className="text-xs text-slate-500">{t("providers")}</div>
                <div className="text-2xl font-bold">{storeSummary.providers}</div>
              </Card>
              <Card className="p-3">
                <div className="text-xs text-slate-500">{t("jobs")}</div>
                <div className="text-2xl font-bold">{storeSummary.jobs}</div>
              </Card>
            </div>

            <Card>
              <CardContent>
                <div className="flex items-center justify-between mb-3">
                  <h2 className="text-lg font-semibold">{t("aiAssistant")}</h2>
                  <div className="flex gap-2">
                    <Button variant="ghost" onClick={() => fetchSummary()}>{t("refresh")}</Button>
                  </div>
                </div>

                <div ref={chatRef} className="h-64 overflow-auto border rounded p-3 bg-white">
                  {chat.length === 0 && <div className="text-slate-400">{t("typeMessage")}</div>}
                  {chat.map((c, i) => (
                    <div key={i} className={`mb-3 ${c.by === "user" ? "text-right" : "text-left"}`}>
                      <div className={`inline-block p-2 rounded ${c.by === "user" ? "bg-sky-50" : "bg-slate-50"}`}>
                        {c.by === "ai" ? <ReactMarkdown>{c.text}</ReactMarkdown> : <div>{c.text}</div>}
                      </div>
                    </div>
                  ))}
                  {typing && <div className="text-sm text-slate-500">AI is typing...</div>}
                </div>

                <div className="mt-4 flex gap-3">
                  <Input placeholder={t("typeMessage")} value={msg} onChange={(e) => setMsg(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handleSend()} />
                  <Button onClick={handleSend} disabled={sending}>{sending ? "Sending..." : t("send")}</Button>
                </div>
                {error && <div className="text-red-600 mt-2">{error}</div>}
              </CardContent>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}