interface SidebarProps {
  namespaces: string[];
  active: string | null;
  onSelect: (ns: string | null) => void;
}

export function Sidebar({ namespaces, active, onSelect }: SidebarProps) {
  return (
    <div className="flex w-48 shrink-0 flex-col overflow-y-auto border-r border-neutral-800 bg-neutral-900">
      <div className="p-3 text-xs font-semibold uppercase tracking-wider text-neutral-500">
        Namespaces
      </div>
      <button
        onClick={() => onSelect(null)}
        className={`px-3 py-2 text-left text-sm transition-colors ${
          active === null
            ? "bg-neutral-800 text-blue-400"
            : "text-neutral-300 hover:bg-neutral-800"
        }`}
      >
        All
      </button>
      {namespaces.map((ns) => (
        <button
          key={ns}
          onClick={() => onSelect(ns)}
          className={`px-3 py-2 text-left text-sm transition-colors ${
            active === ns
              ? "bg-neutral-800 text-blue-400"
              : "text-neutral-300 hover:bg-neutral-800"
          }`}
        >
          {ns}
        </button>
      ))}
    </div>
  );
}
