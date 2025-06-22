root_dir := justfile_directory()
bin_dir := root_dir + "/bin"

project_name := "trivy-lens"

version := if `git rev-parse --git-dir 2>/dev/null; echo $?` == "0" {
    `git describe --tags --always --dirty 2>/dev/null || echo "dev"`
} else {
    `date -u '+%Y%m%d-%H%M%S'`
}
git_commit := `git rev-parse --short HEAD 2>/dev/null || echo "unknown"`
git_branch := `git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown"`
build_time := `date -u '+%Y-%m-%d_%H:%M:%S'`
build_by := `whoami`

ld_flags := "-s -w \
    -X '$(go list -m)/pkg/version.Version=" + version + "' \
    -X '$(go list -m)/pkg/version.Commit=" + git_commit + "' \
    -X '$(go list -m)/pkg/version.Branch=" + git_branch + "' \
    -X '$(go list -m)/pkg/version.BuildTime=" + build_time + "' \
    -X '$(go list -m)/pkg/version.BuildBy=" + build_by + "'"


export GOPATH := env_var_or_default("GOPATH", `go env GOPATH`)
gobin := GOPATH + "/bin"
go := env_var_or_default("GO", "go")

deps:
  go mod tidy
  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
  go install mvdan.cc/gofumpt@latest
  go install golang.org/x/vuln/cmd/govulncheck@latest

build:
  mkdir -p {{bin_dir}}
  go build \
    -ldflags '{{ld_flags}}' \
    -o {{bin_dir}}/{{project_name}} \
    ./cmd/main.go


run: build
  {{bin_dir}}/{{project_name}}

lint:
  {{gobin}}/golangci-lint run --fix

security:
  {{gobin}}/govulncheck ./...
