import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Sidebar } from "./Sidebar";

const namespaces = ["credentials", "ssh", "misc"];

const defaultProps = {
  showRotation: false,
  onRotationToggle: vi.fn(),
};

describe("Sidebar", () => {
  it("always renders an 'All' button", () => {
    render(
      <Sidebar namespaces={[]} active={null} onSelect={vi.fn()} {...defaultProps} />
    );
    expect(screen.getByRole("button", { name: "All" })).toBeInTheDocument();
  });

  it("renders a button for each namespace", () => {
    render(
      <Sidebar
        namespaces={namespaces}
        active={null}
        onSelect={vi.fn()}
        {...defaultProps}
      />
    );
    expect(
      screen.getByRole("button", { name: "credentials" })
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "ssh" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "misc" })).toBeInTheDocument();
  });

  it("always renders a '↻ Rotation' button", () => {
    render(
      <Sidebar namespaces={[]} active={null} onSelect={vi.fn()} {...defaultProps} />
    );
    expect(
      screen.getByRole("button", { name: "↻ Rotation" })
    ).toBeInTheDocument();
  });

  it("calls onSelect(null) when 'All' is clicked", async () => {
    const onSelect = vi.fn();
    const user = userEvent.setup();
    render(
      <Sidebar
        namespaces={namespaces}
        active="ssh"
        onSelect={onSelect}
        {...defaultProps}
      />
    );

    await user.click(screen.getByRole("button", { name: "All" }));

    expect(onSelect).toHaveBeenCalledWith(null);
  });

  it("calls onSelect with namespace name when a namespace button is clicked", async () => {
    const onSelect = vi.fn();
    const user = userEvent.setup();
    render(
      <Sidebar
        namespaces={namespaces}
        active={null}
        onSelect={onSelect}
        {...defaultProps}
      />
    );

    await user.click(screen.getByRole("button", { name: "credentials" }));

    expect(onSelect).toHaveBeenCalledWith("credentials");
  });

  it("calls onRotationToggle when '↻ Rotation' is clicked", async () => {
    const onRotationToggle = vi.fn();
    const user = userEvent.setup();
    render(
      <Sidebar
        namespaces={namespaces}
        active={null}
        onSelect={vi.fn()}
        showRotation={false}
        onRotationToggle={onRotationToggle}
      />
    );

    await user.click(screen.getByRole("button", { name: "↻ Rotation" }));

    expect(onRotationToggle).toHaveBeenCalled();
  });

  it("highlights the active namespace button", () => {
    render(
      <Sidebar
        namespaces={namespaces}
        active="ssh"
        onSelect={vi.fn()}
        {...defaultProps}
      />
    );
    const activeBtn = screen.getByRole("button", { name: "ssh" });
    expect(activeBtn).toHaveClass("text-blue-400");
  });

  it("highlights 'All' when active is null and not in rotation view", () => {
    render(
      <Sidebar
        namespaces={namespaces}
        active={null}
        onSelect={vi.fn()}
        showRotation={false}
        onRotationToggle={vi.fn()}
      />
    );
    expect(screen.getByRole("button", { name: "All" })).toHaveClass(
      "text-blue-400"
    );
  });

  it("highlights '↻ Rotation' when showRotation is true", () => {
    render(
      <Sidebar
        namespaces={namespaces}
        active={null}
        onSelect={vi.fn()}
        showRotation={true}
        onRotationToggle={vi.fn()}
      />
    );
    expect(
      screen.getByRole("button", { name: "↻ Rotation" })
    ).toHaveClass("text-blue-400");
  });

  it("does not highlight 'All' when showRotation is true", () => {
    render(
      <Sidebar
        namespaces={namespaces}
        active={null}
        onSelect={vi.fn()}
        showRotation={true}
        onRotationToggle={vi.fn()}
      />
    );
    expect(screen.getByRole("button", { name: "All" })).not.toHaveClass(
      "text-blue-400"
    );
  });
});
