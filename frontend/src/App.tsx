import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { SearchBar } from "./components/SearchBar";
import { Sidebar } from "./components/Sidebar";
import { SecretList } from "./components/SecretList";
import { SecretDetail } from "./components/SecretDetail";

interface SecretInfo {
  path: string;
  namespace: string;
}

export default function App() {
  const [secrets, setSecrets] = useState<SecretInfo[]>([]);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeNamespace, setActiveNamespace] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke("init_store")
      .then(() => loadSecrets())
      .catch((e) => setError(String(e)));
  }, []);

  async function loadSecrets() {
    try {
      const result = await invoke<SecretInfo[]>("list_secrets", {
        prefix: activeNamespace,
      });
      setSecrets(result);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }

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

  useEffect(() => {
    if (!searchQuery) {
      loadSecrets();
    }
  }, [activeNamespace]);

  const namespaces = [...new Set(secrets.map((s) => s.namespace))].sort();

  return (
    <div className="flex h-screen flex-col">
      <SearchBar query={searchQuery} onSearch={handleSearch} />

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
    </div>
  );
}
