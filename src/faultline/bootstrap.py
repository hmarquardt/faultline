"""Seed local defaults without replacing existing user configuration."""

from faultline.domain import EndpointProfile
from faultline.rubrics import sample_rubric
from faultline.storage import Store


def seed_defaults(store: Store) -> None:
    if not store.profiles():
        for behavior in ("secure", "vulnerable"):
            store.add_profile(
                EndpointProfile(
                    name=f"Mock / {behavior}",
                    authorized=True,
                    mock_behavior=behavior,
                )
            )
    if not store.rubrics():
        store.add_rubric(sample_rubric())
