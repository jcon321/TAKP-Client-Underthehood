#!/usr/bin/env bash
# MCP entry point for Claude Code: sets up the portable node/java/ghidra env, then runs REA's MCP server.
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/env.sh"
exec rea mcp "$@"
