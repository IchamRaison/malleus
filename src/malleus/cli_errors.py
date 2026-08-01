from __future__ import annotations


def format_cli_error(exc: ValueError) -> str:
    errors = getattr(exc, "errors", None)
    if callable(errors):
        try:
            entries = errors(include_input=False)
        except TypeError:
            entries = errors()
        messages: list[str] = []
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                location = ".".join(
                    str(part) for part in entry.get("loc", ()) if part != "__root__"
                )
                message = str(entry.get("msg", "invalid value"))
                messages.append(f"{location}: {message}" if location else message)
        if messages:
            return "; ".join(messages)
    return str(exc)
