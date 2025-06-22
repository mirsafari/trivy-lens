package ui

import "github.com/charmbracelet/bubbles/key"

type keyMap struct {
	Up         key.Binding
	Down       key.Binding
	Filter     key.Binding
	Search     key.Binding
	ExitSearch key.Binding
	Quit       key.Binding
}

var defaultKeyMap = keyMap{
	Up: key.NewBinding(
		key.WithKeys("k", "up"),
		key.WithHelp("↑/k", "move up"),
	),
	Down: key.NewBinding(
		key.WithKeys("j", "down"),
		key.WithHelp("↓/j", "move down"),
	),
	Filter: key.NewBinding(
		key.WithKeys("f"),
		key.WithHelp("f", "filter by severity"),
	),
	Search: key.NewBinding(
		key.WithKeys("/"),
		key.WithHelp("/", "search by name"),
	),
	ExitSearch: key.NewBinding(
		key.WithKeys("enter", "esc"),
		key.WithHelp("enter/esc", "confirm/exit search"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "esc", "ctrl+c"),
		key.WithHelp("q/esc/ctrl+c", "quit"),
	),
}

// Methods to satisfy the interface used by bubbles/help
// Each keymap is separate slice to display them all horizontally
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up},
		{k.Down},
		{k.Quit},
		{k.Filter},
		{k.Search},
		{k.ExitSearch},
	}
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Quit}
}
