"use client";

/**
 * Vault unlock form (ADR-0016 Slice 1 + Slice 4 TOTP).
 *
 * Flow:
 * 1. Master password → derive vaultKey + authHash.
 * 2. Если has_totp: prompt for TOTP code. Decrypt totp_secret под vaultKey.
 *    Verify locally. ADR-0011 §«2FA enforcement» — client-side gate.
 * 3. POST authHash на /vault/unlock. На success — store vaultKey.
 */

import { useRouter } from "next/navigation";
import { useState } from "react";

import { ApiError } from "@/lib/api/client";
import { unlockVault } from "@/lib/api/vault";
import {
  decryptBlob,
  deriveKeys,
  fromBase64,
  toBase64,
} from "@/lib/vault/crypto";
import { setVaultKey } from "@/lib/vault/session";
import { verifyTotpCode } from "@/lib/vault/totp";

interface Props {
  argonSaltB64: string;
  hasTotp: boolean;
  totpSecretEncryptedB64: string | null;
}

type Stage = "password" | "totp";

export default function VaultUnlockForm({
  argonSaltB64,
  hasTotp,
  totpSecretEncryptedB64,
}: Props): JSX.Element {
  const router = useRouter();
  const [stage, setStage] = useState<Stage>("password");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Local-only состояние между stages — vaultKey хранится в session-modu
  // только после полного unlock'а; здесь — derived intermediate, NOT
  // persisted в session до TOTP verify.
  const [pendingKey, setPendingKey] = useState<{
    vaultKey: CryptoKey;
    authHash: Uint8Array;
  } | null>(null);

  async function onPasswordSubmit(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    setError(null);
    if (password.length === 0) {
      setError("Введите master password");
      return;
    }
    setPending(true);
    try {
      const salt = fromBase64(argonSaltB64);
      const { vaultKey, authHash } = await deriveKeys(password, salt);
      if (hasTotp && totpSecretEncryptedB64) {
        // Hold derived state, ask for TOTP.
        setPendingKey({ vaultKey, authHash });
        setStage("totp");
        setPending(false);
        return;
      }
      // Без 2FA — straight unlock.
      await finalizeUnlock(vaultKey, authHash);
    } catch (err) {
      handleError(err);
      setPending(false);
    }
  }

  async function onTotpSubmit(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    setError(null);
    if (!pendingKey || !totpSecretEncryptedB64) {
      setError("Сессия истекла, повторите ввод пароля");
      setStage("password");
      return;
    }
    setPending(true);
    try {
      // Decrypt totp ciphertext под pendingKey.vaultKey.
      const cipher = fromBase64(totpSecretEncryptedB64);
      const totpSecretB64 = await decryptBlob(pendingKey.vaultKey, cipher);
      const totpSecret = fromBase64(totpSecretB64);
      const ok = await verifyTotpCode(totpSecret, totpCode);
      if (!ok) {
        setError("Неверный TOTP-код. Проверьте время и попробуйте ещё.");
        setPending(false);
        return;
      }
      await finalizeUnlock(pendingKey.vaultKey, pendingKey.authHash);
    } catch (err) {
      handleError(err);
      setPending(false);
    }
  }

  async function finalizeUnlock(
    vaultKey: CryptoKey,
    authHash: Uint8Array,
  ): Promise<void> {
    try {
      await unlockVault({ auth_hash_b64: toBase64(authHash) });
      setVaultKey(vaultKey);
      router.refresh();
    } finally {
      setPending(false);
    }
  }

  function handleError(err: unknown): void {
    if (err instanceof ApiError && err.status === 401) {
      setError("Неверный master password");
      setStage("password");
      setPendingKey(null);
    } else if (err instanceof ApiError) {
      setError(`${err.status}: ${err.message}`);
    } else {
      setError(err instanceof Error ? err.message : "Ошибка");
    }
  }

  if (stage === "totp") {
    return (
      <form onSubmit={onTotpSubmit} className="flex flex-col gap-4">
        <p className="text-sm text-gray-600">
          Master password принят. Введите код из приложения-аутентификатора.
        </p>
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium text-gray-700">
            TOTP код <span className="text-red-700">*</span>
          </span>
          <input
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={totpCode}
            onChange={(e) => setTotpCode(e.target.value)}
            maxLength={9}
            required
            placeholder="123 456"
            className="rounded-md border border-gray-300 px-3 py-1.5 font-mono text-sm"
            autoFocus
          />
        </label>
        {error ? (
          <p
            role="alert"
            className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700"
          >
            {error}
          </p>
        ) : null}
        <div className="flex gap-2">
          <button
            type="submit"
            disabled={pending}
            className="rounded-md bg-gray-900 px-4 py-2 text-sm font-medium text-white hover:bg-gray-800 disabled:opacity-50"
          >
            {pending ? "Разблокируем…" : "Подтвердить"}
          </button>
          <button
            type="button"
            disabled={pending}
            onClick={() => {
              setStage("password");
              setPendingKey(null);
              setTotpCode("");
              setError(null);
            }}
            className="rounded-md border border-gray-300 px-3 py-2 text-sm hover:bg-gray-50 disabled:opacity-50"
          >
            Назад
          </button>
        </div>
      </form>
    );
  }

  return (
    <form onSubmit={onPasswordSubmit} className="flex flex-col gap-4">
      <p className="text-sm text-gray-600">
        Vault уже создан. Введите master password — он будет использован
        локально для расшифровки секретов. На сервер передаётся только
        hash от пароля для проверки.
        {hasTotp ? " После пароля потребуется TOTP-код." : ""}
      </p>
      <label className="flex flex-col gap-1 text-sm">
        <span className="font-medium text-gray-700">
          Master password <span className="text-red-700">*</span>
        </span>
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          autoComplete="current-password"
          className="rounded-md border border-gray-300 px-3 py-1.5 text-sm"
          autoFocus
        />
      </label>
      {error ? (
        <p
          role="alert"
          className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700"
        >
          {error}
        </p>
      ) : null}
      <button
        type="submit"
        disabled={pending}
        className="self-start rounded-md bg-gray-900 px-4 py-2 text-sm font-medium text-white hover:bg-gray-800 disabled:opacity-50"
      >
        {pending ? "Проверяем…" : hasTotp ? "Далее" : "Разблокировать"}
      </button>
    </form>
  );
}

