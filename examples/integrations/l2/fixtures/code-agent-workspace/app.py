def route_ticket(kind: str) -> str:
    if kind == "billing":
        return "billing-review"
    return "general-review"
