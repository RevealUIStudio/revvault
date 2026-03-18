//! Built-in TUI editor backed by ratatui + tui-textarea.
//!
//! Call [`edit`] to open the editor. Returns `Some(content)` on save,
//! `None` if the user quit without saving.

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Paragraph},
    Terminal,
};
use tui_textarea::TextArea;

use std::io::{self, Stdout};

/// RAII guard: restores the terminal on drop (including on panic/error).
struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    fn new() -> anyhow::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Best-effort restore — ignore errors during cleanup.
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

/// Open the built-in TUI editor with `content` pre-loaded.
///
/// Returns `Some(new_content)` if the user saved, `None` if they quit without
/// saving.
pub fn edit(secret_path: &str, content: &str) -> anyhow::Result<Option<String>> {
    let mut guard = TerminalGuard::new()?;

    // Populate textarea with the existing content.
    let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let mut textarea = TextArea::new(lines);

    // Style: no border, line numbers, cursor line highlight.
    textarea.set_block(Block::default());
    textarea.set_line_number_style(Style::new().fg(Color::DarkGray));
    textarea.set_cursor_line_style(Style::new().bg(Color::Rgb(40, 40, 40)));

    let original_text = content.to_string();
    let mut pending_quit = false; // tracks whether Ctrl+Q was pressed once already

    loop {
        let title_path = secret_path.to_string();

        guard.terminal.draw(|frame| {
            let area = frame.area();

            // 3-row layout: header (1) | textarea (fill) | footer (1)
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Min(1),
                    Constraint::Length(1),
                ])
                .split(area);

            // Header
            let header = Paragraph::new(Line::from(vec![
                Span::raw("  revvault  ·  "),
                Span::raw(title_path.clone()),
            ]))
            .style(
                Style::new()
                    .bg(Color::DarkGray)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            );
            frame.render_widget(header, chunks[0]);

            // Textarea
            frame.render_widget(&textarea, chunks[1]);

            // Footer
            let footer_text = if pending_quit {
                "  Unsaved changes. Press Ctrl+Q again to discard, or any other key to continue."
            } else {
                "  F2 save   Ctrl+Q quit   Ctrl+Z undo   Ctrl+Y redo"
            };
            let footer = Paragraph::new(footer_text).style(
                Style::new()
                    .bg(Color::DarkGray)
                    .fg(Color::DarkGray),
            );
            frame.render_widget(footer, chunks[2]);
        })?;

        // Block until an event is available.
        let ev = event::read()?;

        match &ev {
            // F2 → save (primary: works in all terminals including Zed)
            Event::Key(KeyEvent {
                code: KeyCode::F(2),
                ..
            }) => {
                let new_content = textarea.lines().join("\n");
                return Ok(Some(new_content));
            }

            // Ctrl+S → save (secondary: works in terminals that don't intercept it)
            Event::Key(KeyEvent {
                code: KeyCode::Char('s'),
                modifiers,
                ..
            }) if modifiers.contains(KeyModifiers::CONTROL) => {
                let new_content = textarea.lines().join("\n");
                return Ok(Some(new_content));
            }

            Event::Key(KeyEvent {
                code: KeyCode::Char('c'),
                modifiers,
                ..
            }) if modifiers.contains(KeyModifiers::CONTROL) => {
                // Ctrl+C → quit without saving (no confirmation needed)
                return Ok(None);
            }

            Event::Key(KeyEvent {
                code: KeyCode::Char('q'),
                modifiers,
                ..
            }) if modifiers.contains(KeyModifiers::CONTROL) => {
                let current_text = textarea.lines().join("\n");
                let changed = current_text != original_text;

                if !changed {
                    // No changes — exit immediately.
                    return Ok(None);
                }

                if pending_quit {
                    // Second Ctrl+Q — discard and quit.
                    return Ok(None);
                } else {
                    // First Ctrl+Q with unsaved changes — show confirmation.
                    pending_quit = true;
                    continue;
                }
            }

            _ => {
                // Any other key resets the pending-quit state.
                if pending_quit {
                    pending_quit = false;
                }
                // Forward the event to tui-textarea.
                textarea.input(ev);
            }
        }
    }
}
