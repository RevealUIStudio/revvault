import { Button } from "@revealui/presentation";

interface SidebarProps {
  namespaces: string[];
  active: string | null;
  onSelect: (ns: string | null) => void;
  showRotation: boolean;
  onRotationToggle: () => void;
}

export function Sidebar({
  namespaces,
  active,
  onSelect,
  showRotation,
  onRotationToggle,
}: SidebarProps) {
  return (
    <div className="flex w-48 shrink-0 flex-col overflow-y-auto border-r border-neutral-800 bg-neutral-900">
      <div className="p-3 text-xs font-semibold uppercase tracking-wider text-neutral-500">
        Namespaces
      </div>
      <Button
        type="button"
        variant="neutral"
        appearance="ghost"
        onClick={() => onSelect(null)}
        className={`justify-start rounded-none px-3 py-2 ${
          active === null && !showRotation ? "bg-neutral-800 text-blue-400" : "text-neutral-300"
        }`}
      >
        All
      </Button>
      {namespaces.map((ns) => (
        <Button
          key={ns}
          type="button"
          variant="neutral"
          appearance="ghost"
          onClick={() => onSelect(ns)}
          className={`justify-start rounded-none px-3 py-2 ${
            active === ns && !showRotation ? "bg-neutral-800 text-blue-400" : "text-neutral-300"
          }`}
        >
          {ns}
        </Button>
      ))}

      <div className="mt-auto border-t border-neutral-800 pt-1">
        <Button
          type="button"
          variant="neutral"
          appearance="ghost"
          onClick={onRotationToggle}
          className={`w-full justify-start rounded-none px-3 py-2 ${
            showRotation ? "bg-neutral-800 text-blue-400" : "text-neutral-300"
          }`}
        >
          ↻ Rotation
        </Button>
      </div>
    </div>
  );
}
