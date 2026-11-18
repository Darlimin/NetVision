"""Project-specific Vulture whitelist.

Names in this file are intentionally kept minimal. Qt callback methods are
discovered through the framework and are already covered by the project's
AST auditor; the standalone ``arg`` entry suppresses the profiler callback
parameter that is required by the hook signature.
"""

arg
