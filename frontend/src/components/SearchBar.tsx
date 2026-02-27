interface SearchBarProps {
  query: string;
  onSearch: (query: string) => void;
}

export function SearchBar({ query, onSearch }: SearchBarProps) {
  return (
    <div className="border-b border-neutral-800 bg-neutral-900 px-4 py-3">
      <input
        type="text"
        value={query}
        onChange={(e) => onSearch(e.target.value)}
        placeholder="Search secrets..."
        className="w-full rounded-md border border-neutral-700 bg-neutral-800 px-3 py-2 text-sm text-neutral-100 placeholder-neutral-500 outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
      />
    </div>
  );
}
