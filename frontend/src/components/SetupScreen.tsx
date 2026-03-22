import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface InitSummary {
  store_dir: string;
  identity_file: string;
  public_key: string;
  store_existed: boolean;
  identity_existed: boolean;
}

interface SetupScreenProps {
  onComplete: () => void;
}

export function SetupScreen({ onComplete }: SetupScreenProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<InitSummary | null>(null);

  async function handleInit() {
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<InitSummary>("init_vault_cmd");
      setSummary(result);
    } catch (e) {
      setError(String(e));
      setLoading(false);
    }
  }

  if (summary) {
    return (
      <div className="flex h-screen items-center justify-center bg-neutral-950">
        <div className="w-full max-w-lg rounded-lg border border-neutral-700 bg-neutral-900 p-8">
          <div className="mb-6 text-2xl font-semibold text-green-400">
            Vault ready
          </div>

          <div className="mb-6 space-y-2 rounded-md border border-neutral-700 bg-neutral-950 p-4 font-mono text-sm text-neutral-300">
            <div>
              <span className="text-neutral-500">Store: </span>
              {summary.store_dir}
            </div>
            <div>
              <span className="text-neutral-500">Identity: </span>
              {summary.identity_file}
            </div>
            <div>
              <span className="text-neutral-500">Public key: </span>
              <span className="break-all text-blue-300">{summary.public_key}</span>
            </div>
          </div>

          <div className="mb-6 rounded-md border border-amber-800 bg-amber-950 px-4 py-3 text-sm text-amber-300">
            <div className="mb-1 font-semibold">Back up your identity file</div>
            If you lose <span className="font-mono">{summary.identity_file}</span>,
            all your secrets are permanently unrecoverable. Store a copy in a
            password manager or secure offline location.
          </div>

          <button
            onClick={onComplete}
            className="w-full rounded-md bg-blue-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-blue-500"
          >
            Open Vault
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen items-center justify-center bg-neutral-950">
      <div className="w-full max-w-lg rounded-lg border border-neutral-700 bg-neutral-900 p-8">
        <div className="mb-2 text-2xl font-semibold text-neutral-100">
          Set up RevVault
        </div>
        <p className="mb-6 text-sm text-neutral-400">
          No vault found. Initialize one to get started — this will create a
          store directory and generate an age encryption key.
        </p>

        {error && (
          <div className="mb-4 rounded-md border border-red-800 bg-red-950 px-3 py-2 text-sm text-red-300">
            {error}
          </div>
        )}

        <div className="mb-6 space-y-2 text-sm text-neutral-400">
          <div className="flex items-start gap-2">
            <span className="mt-0.5 text-neutral-600">→</span>
            <span>
              Store: <span className="font-mono text-neutral-300">~/.revealui/passage-store</span>
            </span>
          </div>
          <div className="flex items-start gap-2">
            <span className="mt-0.5 text-neutral-600">→</span>
            <span>
              Identity: <span className="font-mono text-neutral-300">~/.config/age/keys.txt</span>
            </span>
          </div>
        </div>

        <button
          onClick={handleInit}
          disabled={loading}
          className="w-full rounded-md bg-blue-600 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:opacity-50"
        >
          {loading ? "Initializing..." : "Initialize Vault"}
        </button>
      </div>
    </div>
  );
}
