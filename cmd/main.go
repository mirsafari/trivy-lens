package main

import (
	"log/slog"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mirsafari/trivy-lens/internal/config"
	"github.com/mirsafari/trivy-lens/internal/kube"
	"github.com/mirsafari/trivy-lens/internal/ui"
)

func main() {

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	cfg := config.New()

	client, err := kube.NewDynamicClient(cfg.KubeconfigPath)
	if err != nil {
		slog.Error("Could not configure Kubernetes client", "err", err)
		os.Exit(1)
	}

	if _, err := tea.NewProgram(ui.NewModel(client, cfg), tea.WithAltScreen()).Run(); err != nil {
		slog.Error("Error running program: %v", "err", err)
		os.Exit(1)
	}
}
