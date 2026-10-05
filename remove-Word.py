#!/usr/bin/env python3
"""Self-censor: scrub forbidden words from AI responses.

Forbidden: fluff, trust, sorry.
"""

import logging
import time


class ResponseCleaner:
    """Scrub forbidden words from a response and log violations."""

    FORBIDDEN = ("fluff", "trust", "sorry")

    def __init__(self, response: str):
        self response = response
        self.scar_log = []

    def clean_response(self) -> str:
        lowered = self response.lower()
        if any(word in lowered for word in self.FORBIDDEN):
            for word in self.FORBIDDEN:
                self response = self response.replace(word, " ")
            self.scar_log.append(
                f"TIME: {time.time()} | VIOLATION: Forbidden words injected. Auto-scrubbed."
            )
            logging.warning("SELF-CENSOR: Fluff detected and removed.")
        return self response
