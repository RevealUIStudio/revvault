interface SecretInfo {
  path: string;
  namespace: string;
}

interface SecretListProps {
  secrets: SecretInfo[];
  selected: string | null;
  onSelect: (path: string) => void;
}

export function SecretList({ secrets, selected, onSelect }: SecretListProps) {
  if (secrets.length === 0) {
    return (
      <div className="flex flex-1 items-center justify-center text-neutral-500">
        No secrets found
      </div>
    );
  }

  return (
    <div className="flex w-72 shrink-0 flex-col overflow-y-auto border-r border-neutral-800">
      {secrets.map((secret) => (
        <button
          key={secret.path}
          onClick={() => onSelect(secret.path)}
          className={`border-b border-neutral-800 px-4 py-3 text-left transition-colors ${
            selected === secret.path
              ? "bg-neutral-800"
              : "hover:bg-neutral-800/50"
          }`}
        >
          <div className="truncate text-sm font-medium text-neutral-200">
            {secret.path.split("/").pop()}
          </div>
          <div className="mt-0.5 truncate text-xs text-neutral-500">
            {secret.path}
          </div>
        </button>
      ))}
    </div>
  );
}
