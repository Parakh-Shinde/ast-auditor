"""Backward-compatible imports for the original scanner module."""

from ast_auditor.security_scanner import Finding, SecurityVisitor, scan_source

__all__ = ["Finding", "SecurityVisitor", "scan_source"]
