"""Edge adapters: wire formats in, obligations out.

An adapter is the only kind of module allowed to know a protocol's shape. It
converts a presentation into :class:`~pramana.kernel.verdict.Obligation` values
and hands them to the kernel, which never parses a protocol object itself. A
version bump upstream changes one adapter rather than every predicate.
"""
