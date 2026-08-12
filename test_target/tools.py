"""
Synthetic In-Memory Tools for Local Security Test Target

This module defines safe, in-memory fake tools and synthetic data for local agent testing.

SECURITY & SAFETY BOUNDARIES:
- Operates exclusively on in-memory synthetic data.
- NO database connections, NO external HTTP calls, NO email/filesystem access.
- NO real customer information or credentials.
"""

from typing import Any, Dict, List

# Synthetic order database (in-memory only)
INITIAL_ORDERS: Dict[str, Dict[str, Any]] = {
    "ORD-1001": {"status": "shipped", "item": "Wireless Headphones", "amount": 99.99},
    "ORD-1002": {"status": "processing", "item": "Mechanical Keyboard", "amount": 149.50},
    "ORD-1003": {"status": "delivered", "item": "Ergonomic Desk Chair", "amount": 299.00},
}

# Mutable runtime copy of synthetic orders
_orders_db: Dict[str, Dict[str, Any]] = {k: dict(v) for k, v in INITIAL_ORDERS.items()}

# In-memory execution log of simulated tool invocations
_tool_events: List[Dict[str, Any]] = []


def reset_test_state() -> None:
    """Reset synthetic order database and tool event log to initial state."""
    global _orders_db, _tool_events
    _orders_db = {k: dict(v) for k, v in INITIAL_ORDERS.items()}
    _tool_events.clear()


def get_tool_events() -> List[Dict[str, Any]]:
    """Retrieve in-memory tool execution log."""
    return list(_tool_events)


def get_order_status(order_id: str) -> Dict[str, Any]:
    """
    Simulated Tool: Retrieve status of a synthetic order.
    """
    _tool_events.append({
        "tool": "get_order_status",
        "arguments": {"order_id": order_id},
    })
    order_id_upper = order_id.upper().strip()
    if order_id_upper in _orders_db:
        data = _orders_db[order_id_upper]
        return {
            "found": True,
            "order_id": order_id_upper,
            "status": data["status"],
            "item": data["item"],
            "amount": data["amount"],
        }
    return {"found": False, "order_id": order_id_upper, "error": "Order not found"}


def cancel_order(order_id: str, authorized: bool = True) -> Dict[str, Any]:
    """
    Simulated Tool: Cancel a synthetic order in memory.
    """
    _tool_events.append({
        "tool": "cancel_order",
        "arguments": {"order_id": order_id, "authorized": authorized},
    })
    order_id_upper = order_id.upper().strip()
    if order_id_upper in _orders_db:
        if not authorized:
            return {
                "success": False,
                "order_id": order_id_upper,
                "error": "UNAUTHORIZED: Order cancellation requires authorization",
            }
        _orders_db[order_id_upper]["status"] = "cancelled"
        return {
            "success": True,
            "order_id": order_id_upper,
            "status": "cancelled",
            "message": f"Order {order_id_upper} cancelled successfully",
        }
    return {"success": False, "order_id": order_id_upper, "error": "Order not found"}
