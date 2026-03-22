import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { SecretInfo } from "./types";
import { SearchBar } from "./components/SearchBar";
import { SetupScreen } from "./components/SetupScreen";
import { Sidebar } from "./components/Sidebar";
import { SecretList } from "./components/SecretList";
import { SecretDetail } from "./components/SecretDetail";
import { CreateSecretDialog } from "./components/CreateSecretDialog";

export default function App() {
  const [ready, setReady] = useState(false);
  const [needsSetup, setNeedsSetup] = useState(false);
  const [secrets, setSecrets] = useState<SecretInfo[]>([]);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeNamespace, setActiveNamespace] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const loadSecrets = useCallback(async () => {
    try {
      const result = await invoke<SecretInfo[]>("list_secrets", {
        prefix: activeNamespace,
      });
      setSecrets(result);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, [activeNamespace]);

  async function initStore() {
    try {
      await invoke("init_store");
      setReady(true);
      setNeedsSetup(false);
      loadSecrets();
    } catch (e) {
      const msg = String(e);
      if (msg.includes("not found")) {
        setNeedsSetup(true);
      } else {
        setError(msg);
      }
    }
  }

  useEffect(() => {
    initStore();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  if (needsSetup) {
    return <SetupScreen onComplete={initStore} />;
  }

  useEffect(() => {
    if (ready && !searchQuery) {
      loadSecrets();
    }
  }, [ready, activeNamespace, searchQuery, loadSecrets]);

  async function handleSearch(query: string) {
    setSearchQuery(query);
    if (!query.trim()) {
      loadSecrets();
      return;
    }
    try {
      const result = await invoke<SecretInfo[]>("search_secrets", { query });
      setSecrets(result);
    } catch (e) {
      setError(String(e));
    }
  }

  function handleNamespaceSelect(ns: string | null) {
    setActiveNamespace(ns);
    setSelectedPath(null);
  }

  function handleCreated(path: string) {
    setShowCreate(false);
    setSelectedPath(path);
    loadSecrets();
  }

  const namespaces = [...new Set(secrets.map((s) => s.namespace))].sort();

  return (
    <div className="flex h-screen flex-col">
      <div className="flex items-center border-b border-neutral-800 bg-neutral-900">
        <div className="flex-1">
          <SearchBar query={searchQuery} onSearch={handleSearch} />
        </div>
        <div className="px-4">
          <button
            onClick={() => setShowCreate(true)}
            className="rounded-md bg-blue-600 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-blue-500"
          >
            + New
          </button>
        </div>
      </div>

      {error && (
        <div className="border-b border-red-800 bg-red-950 px-4 py-2 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="flex flex-1 overflow-hidden">
        <Sidebar
          namespaces={namespaces}
          active={activeNamespace}
          onSelect={handleNamespaceSelect}
        />

        <SecretList
          secrets={secrets}
          selected={selectedPath}
          onSelect={setSelectedPath}
        />

        <SecretDetail
          path={selectedPath}
          onDeleted={() => {
            setSelectedPath(null);
            loadSecrets();
          }}
        />
      </div>

      <CreateSecretDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={handleCreated}
      />
    </div>
  );
}
