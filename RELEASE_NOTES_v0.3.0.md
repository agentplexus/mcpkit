# Release Notes - v0.3.0

**Release Date:** 2026-01-18

## Overview

This release marks the transition of the project to its new home as **MCPKit** under `github.com/agentplexus/mcpkit`. The package has been renamed from `mcpruntime` to `mcpkit`, and all import paths have been updated accordingly. This release also includes error handling improvements following Go best practices.

## Installation

```bash
go get github.com/agentplexus/mcpkit@v0.3.0
```

Requires Go 1.24+ and MCP Go SDK v1.2.0+.

## Highlights

- **Project renamed** to MCPKit under `github.com/agentplexus/mcpkit`
- **Package renamed** from `mcpruntime` to `mcpkit`
- **Improved error handling** following Go best practices

## Breaking Changes

This release contains breaking changes that require updates to your import statements:

### Import Path Change

```go
// Before (v0.2.0)
import "github.com/grokify/mcpruntime"

// After (v0.3.0)
import "github.com/agentplexus/mcpkit"
```

### Package Name Change

```go
// Before (v0.2.0)
rt := mcpruntime.New(&mcp.Implementation{...}, nil)
mcpruntime.AddTool(rt, tool, handler)

// After (v0.3.0)
rt := mcpkit.New(&mcp.Implementation{...}, nil)
mcpkit.AddTool(rt, tool, handler)
```

## Upgrade Guide

### From v0.2.0

1. **Update go.mod**:
   ```bash
   go get github.com/agentplexus/mcpkit@v0.3.0
   ```

2. **Update imports** in all Go files:
   - Replace `github.com/grokify/mcpruntime` with `github.com/agentplexus/mcpkit`
   - Replace `github.com/grokify/mcpruntime/oauth2server` with `github.com/agentplexus/mcpkit/oauth2server`

3. **Update package references**:
   - Replace `mcpruntime.` with `mcpkit.`

4. **Remove old dependency**:
   ```bash
   go mod tidy
   ```

### Quick Migration Script

```bash
# In your project directory
find . -name "*.go" -exec sed -i '' \
  -e 's|github.com/grokify/mcpruntime|github.com/agentplexus/mcpkit|g' \
  -e 's|mcpruntime\.|mcpkit.|g' {} \;
go mod tidy
```

## What's Changed

### Changed

- Module path changed from `github.com/grokify/mcpruntime` to `github.com/agentplexus/mcpkit`
- Package name changed from `mcpruntime` to `mcpkit`
- All import paths updated to use new module path

### Fixed

- Error handling for `fmt.Fprintf` in OAuth login error page now logs errors via `slog.Logger`
- Error handling for `resp.Body.Close()` in all test files now reports errors via `t.Logf`

## API Compatibility

All APIs remain functionally identical to v0.2.0. Only the import path and package name have changed:

| v0.2.0 | v0.3.0 |
|--------|--------|
| `mcpruntime.New()` | `mcpkit.New()` |
| `mcpruntime.AddTool()` | `mcpkit.AddTool()` |
| `mcpruntime.Options` | `mcpkit.Options` |
| `mcpruntime.HTTPServerOptions` | `mcpkit.HTTPServerOptions` |
| `mcpruntime.OAuth2Options` | `mcpkit.OAuth2Options` |

## Contributors

- John Wang

## Links

- [GitHub Repository](https://github.com/agentplexus/mcpkit)
- [Go Package Documentation](https://pkg.go.dev/github.com/agentplexus/mcpkit)
- [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
