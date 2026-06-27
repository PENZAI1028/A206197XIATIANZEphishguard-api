"""Compatibility entry point for the existing root-based Render service."""

from phishguard.backend.app import app


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

