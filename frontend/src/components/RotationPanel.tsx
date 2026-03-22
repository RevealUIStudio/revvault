import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { ProviderInfo } from "../types";

type ProviderStatus =
  | { type: "idle" }
  | { type: "running" }
  | { type: "success" }
  | { type: "error"; message: string };

export function RotationPanel() {
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [statuses, setStatuses] = useState<Record<string, ProviderStatus>>({});

  const loadProviders = useCallback(async () => {
    try {
      const result = await invoke<ProviderInfo[]>("list_rotation_providers");
      setProviders(result);
      setLoadError(null);
    } catch (e) {
      setLoadError(String(e));
    }
  }, []);

  useEffect(() => {
    loadProviders();
  }, [loadProviders]);

  async function handleRotate(name: string) {
    setStatuses((prev) => ({ ...prev, [name]: { type: "running" } }));
    try {
      await invoke("rotate_secret", { providerName: name });
      setStatuses((prev) => ({ ...prev, [name]: { type: "success" } }));
    } catch (e) {
      setStatuses((prev) => ({
        ...prev,
        [name]: { type: "error", message: String(e) },
      }));
    }
  }

  return (
    <div className="flex flex-1 flex-col overflow-y-auto p-6">
      <div className="mb-6">
        <h2 className="text-lg font-semibold text-neutral-100">
          Rotation Providers
        </h2>
        <p className="mt-1 text-sm text-neutral-500">
          Configured in{" "}
          <span className="font-mono text-neutral-400">
            .revvault/rotation.toml
          </span>
        </p>
      </div>

      {loadError && (
        <div className="mb-4 rounded-md border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {loadError}
        </div>
      )}

      {!loadError && providers.length === 0 && (
        <div className="rounded-md border border-neutral-700 bg-neutral-900 px-4 py-8 text-center text-sm text-neutral-500">
          No providers configured.
          <br />
          Add a{" "}
          <span className="font-mono text-neutral-400">
            [providers.name]
          </span>{" "}
          block to{" "}
          <span className="font-mono text-neutral-400">
            .revvault/rotation.toml
          </span>
          .
        </div>
      )}

      <div className="space-y-3">
        {providers.map((p) => {
          const status: ProviderStatus = statuses[p.name] ?? { type: "idle" };
          return (
            <ProviderRow
              key={p.name}
              provider={p}
              status={status}
              onRotate={() => handleRotate(p.name)}
            />
          );
        })}
      </div>
    </div>
  );
}

interface ProviderRowProps {
  provider: ProviderInfo;
  status: ProviderStatus;
  onRotate: () => void;
}

function ProviderRow({ provider, status, onRotate }: ProviderRowProps) {
  const running = status.type === "running";

  return (
    <div className="rounded-md border border-neutral-700 bg-neutral-900 p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="font-medium text-neutral-100">{provider.name}</div>
          <div className="mt-0.5 truncate font-mono text-xs text-neutral-500">
            {provider.secret_path}
          </div>
          {status.type === "success" && (
            <div className="mt-1.5 text-xs text-green-400">
              ✓ Rotated successfully
            </div>
          )}
          {status.type === "error" && (
            <div className="mt-1.5 text-xs text-red-400">{status.message}</div>
          )}
        </div>

        <button
          onClick={onRotate}
          disabled={running}
          className="shrink-0 rounded-md bg-neutral-800 px-3 py-1.5 text-sm font-medium text-neutral-200 transition-colors hover:bg-neutral-700 disabled:opacity-50"
        >
          {running ? "Rotating…" : "Rotate"}
        </button>
      </div>
    </div>
  );
}
