import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface CreateSecretDialogProps {
  open: boolean;
  onClose: () => void;
  onCreated: (path: string) => void;
}

export function CreateSecretDialog({
  open,
  onClose,
  onCreated,
}: CreateSecretDialogProps) {
  const [path, setPath] = useState("");
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  if (!open) return null;

  function reset() {
    setPath("");
    setValue("");
    setError(null);
    setSaving(false);
  }

  function handleClose() {
    reset();
    onClose();
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    const trimmedPath = path.trim();
    const trimmedValue = value.trim();

    if (!trimmedPath || !trimmedValue) {
      setError("Path and value are required.");
      return;
    }

    setSaving(true);
    setError(null);

    try {
      await invoke("set_secret", {
        path: trimmedPath,
        value: trimmedValue,
        force: false,
      });
      const createdPath = trimmedPath;
      reset();
      onCreated(createdPath);
    } catch (e) {
      setError(String(e));
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-md rounded-lg border border-neutral-700 bg-neutral-900 p-6 shadow-xl"
      >
        <h2 className="mb-4 text-lg font-semibold text-neutral-100">
          Create Secret
        </h2>

        {error && (
          <div className="mb-3 rounded-md border border-red-800 bg-red-950 px-3 py-2 text-sm text-red-300">
            {error}
          </div>
        )}

        <label className="mb-1 block text-sm font-medium text-neutral-400">
          Path
        </label>
        <input
          type="text"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          placeholder="credentials/stripe/secret-key"
          className="mb-4 w-full rounded-md border border-neutral-700 bg-neutral-800 px-3 py-2 text-sm text-neutral-100 placeholder-neutral-500 outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          autoFocus
        />

        <label className="mb-1 block text-sm font-medium text-neutral-400">
          Value
        </label>
        <textarea
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="Secret value..."
          rows={4}
          className="mb-4 w-full resize-none rounded-md border border-neutral-700 bg-neutral-800 px-3 py-2 font-mono text-sm text-neutral-100 placeholder-neutral-500 outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
        />

        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={handleClose}
            className="rounded-md bg-neutral-800 px-4 py-2 text-sm font-medium text-neutral-300 transition-colors hover:bg-neutral-700"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={saving}
            className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:opacity-50"
          >
            {saving ? "Creating..." : "Create"}
          </button>
        </div>
      </form>
    </div>
  );
}
