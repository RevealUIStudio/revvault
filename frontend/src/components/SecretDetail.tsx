import { Button } from "@revealui/presentation";
import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface SecretDetailProps {
  path: string | null;
  onDeleted: () => void;
}

const REVEAL_TTL_MS = 15_000;

export function SecretDetail({ path, onDeleted }: SecretDetailProps) {
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const revealEl = useRef<HTMLPreElement>(null);
  const revealTimer = useRef<number | null>(null);

  function clearReveal() {
    if (revealEl.current) {
      revealEl.current.textContent = "";
    }
    if (revealTimer.current !== null) {
      window.clearTimeout(revealTimer.current);
      revealTimer.current = null;
    }
    setRevealed(false);
  }

  useEffect(() => {
    clearReveal();
    setCopied(false);
    setError(null);
  }, [path]);

  useEffect(() => () => clearReveal(), []);

  if (!path) {
    return (
      <div className="flex flex-1 items-center justify-center text-neutral-500">
        Select a secret to view details
      </div>
    );
  }

  async function handleReveal() {
    if (revealed) {
      clearReveal();
      return;
    }

    setLoading(true);
    setError(null);
    try {
      // Short-lived display only — never stored in React state.
      const result = await invoke<string>("get_secret", { path });
      if (revealEl.current) {
        revealEl.current.textContent = result;
      }
      setRevealed(true);
      revealTimer.current = window.setTimeout(() => {
        clearReveal();
      }, REVEAL_TTL_MS);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function handleCopy() {
    setError(null);
    try {
      await invoke("copy_secret", { path });
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (e) {
      setError(String(e));
    }
  }

  async function handleDelete() {
    if (!confirm(`Delete "${path}"?`)) return;
    setError(null);
    try {
      await invoke("delete_secret", { path });
      onDeleted();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="flex flex-1 flex-col p-6">
      <div className="mb-6">
        <h2 className="text-lg font-semibold text-neutral-100">{path}</h2>
        <div className="mt-1 text-sm text-neutral-500">
          Namespace: {path.split("/")[0]}
        </div>
      </div>

      <div className="mb-4 rounded-md border border-neutral-700 bg-neutral-900 p-4">
        <pre
          ref={revealEl}
          className={`whitespace-pre-wrap break-all font-mono text-sm text-neutral-200 ${
            revealed ? "" : "hidden"
          }`}
        />
        {!revealed && (
          <div className="font-mono text-sm text-neutral-600">
            {"*".repeat(32)}
          </div>
        )}
      </div>

      {error && (
        <div className="mb-4 rounded-md border border-red-800 bg-red-950 px-3 py-2 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="flex gap-2">
        <Button
          type="button"
          variant="neutral"
          appearance="solid"
          onClick={handleReveal}
          disabled={loading}
          isLoading={loading}
        >
          {revealed ? "Hide" : "Reveal"}
        </Button>

        <Button type="button" variant="brand" appearance="solid" onClick={handleCopy}>
          {copied ? "Copied!" : "Copy"}
        </Button>

        <Button type="button" variant="danger" appearance="solid" onClick={handleDelete}>
          Delete
        </Button>
      </div>
    </div>
  );
}
