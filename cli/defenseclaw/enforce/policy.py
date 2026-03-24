"""PolicyEngine — thin facade over the audit Store for enforcement decisions.

Mirrors internal/enforce/policy.go exactly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from defenseclaw.models import ActionEntry, ActionState

if TYPE_CHECKING:
    from defenseclaw.db import Store


class PolicyEngine:
    def __init__(self, store: Store | None) -> None:
        self.store = store

    def is_blocked(self, target_type: str, name: str) -> bool:
        if not self.store:
            return False
        return self.store.has_action(target_type, name, "install", "block")

    def is_allowed(self, target_type: str, name: str) -> bool:
        if not self.store:
            return False
        return self.store.has_action(target_type, name, "install", "allow")

    def is_quarantined(self, target_type: str, name: str) -> bool:
        if not self.store:
            return False
        return self.store.has_action(target_type, name, "file", "quarantine")

    def block(self, target_type: str, name: str, reason: str) -> None:
        if self.store:
            self.store.set_action_field(target_type, name, "install", "block", reason)

    def allow(self, target_type: str, name: str, reason: str) -> None:
        if self.store:
            self.store.set_action_field(target_type, name, "install", "allow", reason)

    def unblock(self, target_type: str, name: str) -> None:
        if self.store:
            self.store.clear_action_field(target_type, name, "install")

    def quarantine(self, target_type: str, name: str, reason: str) -> None:
        if self.store:
            self.store.set_action_field(target_type, name, "file", "quarantine", reason)

    def clear_quarantine(self, target_type: str, name: str) -> None:
        if self.store:
            self.store.clear_action_field(target_type, name, "file")

    def disable(self, target_type: str, name: str, reason: str) -> None:
        if self.store:
            self.store.set_action_field(target_type, name, "runtime", "disable", reason)

    def enable(self, target_type: str, name: str) -> None:
        if self.store:
            self.store.clear_action_field(target_type, name, "runtime")

    def set_source_path(self, target_type: str, name: str, path: str) -> None:
        if self.store:
            self.store.set_source_path(target_type, name, path)

    def set_action(
        self, target_type: str, name: str, source_path: str,
        state: ActionState, reason: str,
    ) -> None:
        if self.store:
            self.store.set_action(target_type, name, source_path, state, reason)

    def get_action(self, target_type: str, name: str) -> ActionEntry | None:
        if not self.store:
            return None
        return self.store.get_action(target_type, name)

    def list_blocked(self) -> list[ActionEntry]:
        if not self.store:
            return []
        return self.store.list_by_action("install", "block")

    def list_allowed(self) -> list[ActionEntry]:
        if not self.store:
            return []
        return self.store.list_by_action("install", "allow")

    def list_all(self) -> list[ActionEntry]:
        if not self.store:
            return []
        return self.store.list_all_actions()

    def list_by_type(self, target_type: str) -> list[ActionEntry]:
        if not self.store:
            return []
        return self.store.list_actions_by_type(target_type)

    def remove_action(self, target_type: str, name: str) -> None:
        if self.store:
            self.store.remove_action(target_type, name)
