import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { RotationPanel } from "./RotationPanel";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";
const mockInvoke = vi.mocked(invoke);

const mockProviders = [
  { name: "github", secret_path: "credentials/github/token" },
  { name: "vercel", secret_path: "credentials/vercel/token" },
];

describe("RotationPanel", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });

  it("renders the heading", () => {
    mockInvoke.mockResolvedValue([]);
    render(<RotationPanel />);
    expect(screen.getByText("Rotation Providers")).toBeInTheDocument();
  });

  it("shows empty state when no providers are configured", async () => {
    mockInvoke.mockResolvedValue([]);
    render(<RotationPanel />);

    await waitFor(() =>
      expect(
        screen.getByText(/No providers configured/)
      ).toBeInTheDocument()
    );
  });

  it("renders a row for each configured provider", async () => {
    mockInvoke.mockResolvedValue(mockProviders);
    render(<RotationPanel />);

    await waitFor(() =>
      expect(screen.getByText("github")).toBeInTheDocument()
    );
    expect(screen.getByText("vercel")).toBeInTheDocument();
    expect(
      screen.getByText("credentials/github/token")
    ).toBeInTheDocument();
    expect(
      screen.getByText("credentials/vercel/token")
    ).toBeInTheDocument();
  });

  it("renders a 'Rotate' button for each provider", async () => {
    mockInvoke.mockResolvedValue(mockProviders);
    render(<RotationPanel />);

    await waitFor(() =>
      expect(screen.getAllByRole("button", { name: "Rotate" })).toHaveLength(2)
    );
  });

  it("calls rotate_secret with the provider name when Rotate is clicked", async () => {
    const user = userEvent.setup();
    mockInvoke
      .mockResolvedValueOnce(mockProviders)  // list_rotation_providers
      .mockResolvedValueOnce(undefined);     // rotate_secret

    render(<RotationPanel />);

    await waitFor(() =>
      expect(screen.getAllByRole("button", { name: "Rotate" })).toHaveLength(2)
    );

    await user.click(screen.getAllByRole("button", { name: "Rotate" })[0]);

    await waitFor(() =>
      expect(mockInvoke).toHaveBeenCalledWith("rotate_secret", {
        providerName: "github",
      })
    );
  });

  it("shows 'Rotating…' while rotation is in progress", async () => {
    const user = userEvent.setup();
    let resolveRotation!: () => void;
    const pending = new Promise<void>((r) => {
      resolveRotation = r;
    });

    mockInvoke
      .mockResolvedValueOnce(mockProviders)
      .mockImplementationOnce(() => pending);

    render(<RotationPanel />);

    await waitFor(() =>
      expect(screen.getAllByRole("button", { name: "Rotate" })).toHaveLength(2)
    );

    await user.click(screen.getAllByRole("button", { name: "Rotate" })[0]);

    expect(screen.getByRole("button", { name: "Rotating…" })).toBeInTheDocument();

    resolveRotation();
  });

  it("shows success message after rotation completes", async () => {
    const user = userEvent.setup();
    mockInvoke
      .mockResolvedValueOnce(mockProviders)
      .mockResolvedValueOnce(undefined);

    render(<RotationPanel />);

    await waitFor(() =>
      expect(screen.getAllByRole("button", { name: "Rotate" })).toHaveLength(2)
    );

    await user.click(screen.getAllByRole("button", { name: "Rotate" })[0]);

    await waitFor(() =>
      expect(screen.getByText("✓ Rotated successfully")).toBeInTheDocument()
    );
  });

  it("shows error message when rotation fails", async () => {
    const user = userEvent.setup();
    mockInvoke
      .mockResolvedValueOnce(mockProviders)
      .mockRejectedValueOnce("API rate limit exceeded");

    render(<RotationPanel />);

    await waitFor(() =>
      expect(screen.getAllByRole("button", { name: "Rotate" })).toHaveLength(2)
    );

    await user.click(screen.getAllByRole("button", { name: "Rotate" })[0]);

    await waitFor(() =>
      expect(
        screen.getByText("API rate limit exceeded")
      ).toBeInTheDocument()
    );
  });

  it("shows load error banner when list_rotation_providers fails", async () => {
    mockInvoke.mockRejectedValueOnce("store not initialized");
    render(<RotationPanel />);

    await waitFor(() =>
      expect(
        screen.getByText("store not initialized")
      ).toBeInTheDocument()
    );
  });

  it("does not affect other providers when one is rotated", async () => {
    const user = userEvent.setup();
    mockInvoke
      .mockResolvedValueOnce(mockProviders)
      .mockResolvedValueOnce(undefined);

    render(<RotationPanel />);

    await waitFor(() =>
      expect(screen.getAllByRole("button", { name: "Rotate" })).toHaveLength(2)
    );

    await user.click(screen.getAllByRole("button", { name: "Rotate" })[0]);

    await waitFor(() =>
      expect(screen.getByText("✓ Rotated successfully")).toBeInTheDocument()
    );

    // vercel has no success or error message — only github was rotated
    expect(
      screen.getAllByText("✓ Rotated successfully")
    ).toHaveLength(1);
  });
});
