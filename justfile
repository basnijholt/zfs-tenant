# zfs-tenant Development Commands
# Run `just` to see available commands

# Default: list available commands
default:
    @just --list

# Install development dependencies
install:
    uv sync --dev

# Run the unit tests (parallel)
test:
    uv run pytest -n auto

# Lint, format, and type check
lint:
    uv run ruff check --fix .
    uv run ruff format .
    uv run mypy src tests
    uv run ty check

# Build the single-file zipapp used on hosts without pip (e.g. TrueNAS SCALE)
pyz:
    uv run python scripts/build_pyz.py
    uv run python dist/zfs-tenant.pyz --version

# Run the two-node NixOS VM test against real OpenZFS and syncoid
vm-test:
    nix build .#checks.x86_64-linux.integration --no-link -L

# Regenerate docs/ from README.md sections and build the site
docs:
    uv run --group docs markdown-code-runner docs/*.md
    uv run --group docs zensical build

# Serve the docs site locally with live reload
docs-serve:
    uv run --group docs markdown-code-runner docs/*.md
    uv run --group docs zensical serve

# Clean up build artifacts and caches
clean:
    rm -rf .pytest_cache .mypy_cache .ruff_cache dist build result site
    find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
