// web/src/Biometric.tsx
// -------------------------------------------------------------
// Enterprise Biometric Login & Registration — WebAuthn / FaceID / Fingerprint
// For NebulaCore Dashboard — production-grade version
// -------------------------------------------------------------

import React, { useState, useEffect } from "react";

/** Helpers: base64url <-> ArrayBuffer conversions */
function base64UrlToBuffer(base64url: string): ArrayBuffer {
  const padding = "=".repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = window.atob(base64);
  const buf = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; ++i) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}

function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  // safe chunking for larger buffers
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  const base64 = window.btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Fetch WebAuthn assertion challenge from backend */
async function getChallenge() {
  const res = await fetch("/api/v1/auth/webauthn/challenge");
  if (!res.ok) throw new Error("فشل الحصول على التحدي من الخادم");
  return res.json();
}

/** Fetch registration (creation) options from backend */
async function getRegisterOptions() {
  const res = await fetch("/api/v1/auth/webauthn/register/options");
  if (!res.ok) throw new Error("فشل الحصول على خيارات التسجيل من الخادم");
  return res.json();
}

/** Perform biometric authentication (assertion) */
async function performBiometricAuth() {
  const challengeData = await getChallenge();
  const publicKey: any = {
    ...challengeData,
    challenge: base64UrlToBuffer(challengeData.challenge),
    allowCredentials: challengeData.allowCredentials?.map((c: any) => ({
      ...c,
      id: base64UrlToBuffer(c.id)
    }))
  };

  const credential: any = await navigator.credentials.get({ publicKey });
  if (!credential) throw new Error("لا توجد بيانات اعتماد تم إرجاعها");

  const auth = credential.response;

  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64Url(auth.clientDataJSON),
      authenticatorData: bufferToBase64Url(auth.authenticatorData),
      signature: bufferToBase64Url(auth.signature),
      userHandle: auth.userHandle ? bufferToBase64Url(auth.userHandle) : null
    }
  };
}

/** Perform biometric registration (attestation) */
async function performBiometricRegister(displayName = "Nebula Device") {
  const options = await getRegisterOptions();

  // prepare PublicKeyCredentialCreationOptions
  const publicKey: any = {
    ...options,
    challenge: base64UrlToBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64UrlToBuffer(options.user.id) // ensure ArrayBuffer
    },
    excludeCredentials: options.excludeCredentials?.map((c: any) => ({
      ...c,
      id: base64UrlToBuffer(c.id)
    }))
  };

  // create credential
  const cred: any = await navigator.credentials.create({ publicKey });
  if (!cred) throw new Error("لم يتم إنشاء بيانات الاعتماد");

  const att = cred.response;
  const payload = {
    id: cred.id,
    rawId: bufferToBase64Url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToBase64Url(att.clientDataJSON),
      attestationObject: bufferToBase64Url((att as any).attestationObject),
      // userHandle not present for create in most flows
    },
    displayName
  };

  // send to server to finish registration
  const res = await fetch("/api/v1/auth/webauthn/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error("فشل إتمام التسجيل: " + txt);
  }
  return res.json();
}

/** Optional: fetch registered devices for current user (server-side endpoint optional) */
async function listDevices() {
  const res = await fetch("/api/v1/auth/webauthn/devices");
  if (!res.ok) return [];
  return res.json();
}

/** Main Component */
export default function Biometric() {
  const [status, setStatus] = useState<string | null>(null);
  const [supported, setSupported] = useState<boolean>(false);
  const [devices, setDevices] = useState<Array<any>>([]);
  const [loadingDevices, setLoadingDevices] = useState(false);

  useEffect(() => {
    setSupported(
      typeof window.PublicKeyCredential !== "undefined" &&
        !!navigator.credentials
    );
    // attempt to fetch devices if endpoint exists
    (async () => {
      setLoadingDevices(true);
      try {
        const d = await listDevices();
        setDevices(d || []);
      } catch (e) {
        // ignore if not supported server-side
      } finally {
        setLoadingDevices(false);
      }
    })();
  }, []);

  /** Login handler */
  async function handleLogin() {
    if (!supported) {
      setStatus("هذا المتصفح لا يدعم المصادقة البيومترية (WebAuthn)");
      return;
    }

    setStatus("جاري التحقق...");
    try {
      const assertion = await performBiometricAuth();
      const res = await fetch("/api/v1/auth/webauthn/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(assertion)
      });

      if (!res.ok) throw new Error("فشل التحقق من البصمة");

      setStatus("✅ تم تسجيل الدخول بنجاح!");
    } catch (err: any) {
      console.error(err);
      setStatus("❌ فشل التحقق — حاول مجددًا أو استخدم رمز PIN");
    }
  }

  /** Registration handler */
  async function handleRegister() {
    if (!supported) {
      setStatus("هذا المتصفح لا يدعم المصادقة البيومترية (WebAuthn)");
      return;
    }
    setStatus("جاري إعداد تسجيل الجهاز...");
    try {
      const result = await performBiometricRegister("NebulaCore Device");
      setStatus("✅ تم تسجيل الجهاز بنجاح!");
      // reload devices list if available
      try {
        const d = await listDevices();
        setDevices(d || []);
      } catch {}
      return result;
    } catch (err: any) {
      console.error(err);
      setStatus("❌ فشل تسجيل الجهاز: " + (err.message || err));
    }
  }

  /** Optional fallback: use PIN or OTP */
  async function handleFallback() {
    setStatus("استخدم طريقة بديلة لتسجيل الدخول...");
    window.location.href = "/login/pin";
  }

  return (
    <div className="flex flex-col items-center justify-center text-center p-6 space-y-4">
      <h2 className="text-xl font-semibold text-gray-100">
        تسجيل / دخول بالبصمة و WebAuthn — NebulaCore
      </h2>

      <div className="flex flex-col sm:flex-row gap-3">
        <button
          onClick={handleLogin}
          disabled={!supported}
          className="px-6 py-3 bg-blue-600 hover:bg-blue-700 rounded-2xl text-white font-medium shadow-lg transition"
        >
          🔒 تسجيل الدخول بالبصمة / الوجه
        </button>

        <button
          onClick={handleRegister}
          disabled={!supported}
          className="px-6 py-3 bg-green-600 hover:bg-green-700 rounded-2xl text-white font-medium shadow-lg transition"
        >
          ➕ تسجيل جهاز جديد
        </button>

        <button
          onClick={handleFallback}
          className="px-4 py-2 bg-gray-700 hover:bg-gray-800 text-sm text-gray-200 rounded-xl"
        >
          طريقة بديلة (PIN / رمز مؤقت)
        </button>
      </div>

      {status && (
        <div className="mt-4 text-sm text-gray-300 bg-gray-800 px-3 py-2 rounded-xl shadow-inner w-full max-w-xl">
          {status}
        </div>
      )}

      <div className="w-full max-w-xl mt-4 text-left">
        <h3 className="text-sm font-semibold text-gray-200 mb-2">الأجهزة المسجلة</h3>
        {loadingDevices ? (
          <div className="text-sm text-gray-400">جاري تحميل...</div>
        ) : devices.length === 0 ? (
          <div className="text-sm text-gray-400">لا توجد أجهزة مسجلة.</div>
        ) : (
          <ul className="space-y-2">
            {devices.map((d: any, i: number) => (
              <li key={i} className="flex justify-between items-center bg-gray-900/40 p-2 rounded-md">
                <div>
                  <div className="text-sm text-gray-100">{d.name || d.id}</div>
                  <div className="text-xs text-gray-400">{d.createdAt || d.registeredAt}</div>
                </div>
                <div className="text-xs text-gray-300">{d.transports ? d.transports.join(", ") : ""}</div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
    }
    