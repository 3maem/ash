"""
ASH Client for Python.

Generate ASH proofs for HTTP requests.

Example:
    from ash.client import AshClient

    client = AshClient()

    # Get context from server
    ctx = requests.post("http://api.example.com/ash/context").json()

    # Build proof for request
    headers = client.build_headers(
        context_id=ctx["contextId"],
        mode=ctx["mode"],
        binding="POST /api/update",
        payload={"name": "John"},
        nonce=ctx.get("nonce"),
    )

    # Make request with ASH headers
    response = requests.post(
        "http://api.example.com/api/update",
        json={"name": "John"},
        headers=headers,
    )
"""

from typing import Any, Dict, Optional

from ash.core.canonicalize import ash_canonicalize_json, ash_canonicalize_url_encoded
from ash.core.proof import ash_build_proof
from ash.core.types import AshMode, BuildProofInput, SupportedContentType


class AshClient:
    """
    ASH client for generating request proofs.

    Attributes:
        context_id_header: Header name for context ID (default: X-Ash-Context-Id)
        proof_header: Header name for proof (default: X-Ash-Proof)
    """

    def __init__(
        self,
        context_id_header: str = "X-Ash-Context-Id",
        proof_header: str = "X-Ash-Proof",
    ):
        self.context_id_header = context_id_header
        self.proof_header = proof_header

    def generate_proof(
        self,
        context_id: str,
        mode: AshMode,
        binding: str,
        payload: Any,
        content_type: SupportedContentType = "application/json",
        nonce: Optional[str] = None,
    ) -> str:
        """
        Generate an ASH proof for a request.

        Args:
            context_id: Server-issued context ID
            mode: Security mode from context
            binding: Request binding (e.g., "POST /api/update")
            payload: Request payload (dict for JSON, string for form data)
            content_type: Content type (default: application/json)
            nonce: Optional server-issued nonce

        Returns:
            Base64URL-encoded proof string
        """
        # Canonicalize payload
        if content_type == "application/json":
            canonical_payload = ash_canonicalize_json(payload)
        elif content_type == "application/x-www-form-urlencoded":
            canonical_payload = ash_canonicalize_url_encoded(payload)
        else:
            raise ValueError(f"Unsupported content type: {content_type}")

        # Build proof
        return ash_build_proof(
            BuildProofInput(
                mode=mode,
                binding=binding,
                context_id=context_id,
                canonical_payload=canonical_payload,
                nonce=nonce,
            )
        )

    def build_headers(
        self,
        context_id: str,
        mode: AshMode,
        binding: str,
        payload: Any,
        content_type: SupportedContentType = "application/json",
        nonce: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Build HTTP headers with ASH context ID and proof.

        Args:
            context_id: Server-issued context ID
            mode: Security mode from context
            binding: Request binding (e.g., "POST /api/update")
            payload: Request payload
            content_type: Content type (default: application/json)
            nonce: Optional server-issued nonce

        Returns:
            Dict with X-Ash-Context-Id and X-Ash-Proof headers
        """
        proof = self.generate_proof(
            context_id=context_id,
            mode=mode,
            binding=binding,
            payload=payload,
            content_type=content_type,
            nonce=nonce,
        )

        return {
            self.context_id_header: context_id,
            self.proof_header: proof,
        }


def create_client(
    context_id_header: str = "X-Ash-Context-Id",
    proof_header: str = "X-Ash-Proof",
) -> AshClient:
    """
    Create an ASH client instance.

    Args:
        context_id_header: Header name for context ID
        proof_header: Header name for proof

    Returns:
        Configured AshClient instance
    """
    return AshClient(
        context_id_header=context_id_header,
        proof_header=proof_header,
    )
