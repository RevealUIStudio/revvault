import { Button } from "@revealui/presentation";
import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface SecretDetailProps {
  path: string | null;
  onDeleted: () => void;
}

export function SecretDetail({ path, onDeleted }: SecretDetailProps) {
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setCopied(false);
    setError(null);
  }, [path]);

  if (!path) {
    return (
      <div className="flex flex-1 items-center justify-center text-neutral-500">
        Select a secret to view details
      </div>
    );
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
        <div className="font-mono text-sm text-neutral-600">
          {"*".repeat(32)}
        </div>
        <p className="mt-3 text-sm text-neutral-500">
          Value stays in native code. Use Copy to place it on the clipboard
          (clears after 45s), or <code className="font-mono">revvault get</code>{" "}
          in a vault-private terminal.
        </p>
      </div>

      {error && (
        <div className="mb-4 rounded-md border border-red-800 bg-red-950 px-3 py-2 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="flex gap-2">
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
