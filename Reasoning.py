"""Reasoning module — chat client wrapper.

The client is injected at runtime (e.g., by the bridge or server).
This file is a snippet, not a standalone module: it assumes `client`
is defined in the importing namespace.
"""


def create_chat(client, model: str = "supergrok-heavy-4-2", store_messages: bool = True, use_encrypted_content: bool = True):
    """Create a chat session using the injected client."""
    return client.chat.create(
        model=model,
        store_messages=store_messages,
        use_encrypted_content=use_encrypted_content,
    )
