from __future__ import annotations

from pydantic import Field, SecretStr

from .contracts import ExecutionContext, Model
from .credentials import AgentVaultCredentialResolver, CredentialResolutionError


class SandboxBrokerSession(Model):
    proxy_url: SecretStr = Field(alias="proxyUrl")
    ca_certificate: str = Field(alias="caCertificate", min_length=1)


class AgentVaultSandboxBroker:
    """Mint short-lived Agent Vault sessions for a policy-approved sandbox profile.

    The requested host set must exactly match the opaque credential binding's
    host scope. A narrower profile therefore needs a narrower credential handle;
    this prevents UCS from advertising a per-request restriction that the
    underlying broker session may not enforce.
    """

    def __init__(self, resolver: AgentVaultCredentialResolver) -> None:
        self.resolver = resolver

    async def sandbox_session(
        self,
        service_id: str,
        allowed_hosts: tuple[str, ...],
        ctx: ExecutionContext,
    ) -> SandboxBrokerSession:
        if ctx.credential_handle is None:
            raise CredentialResolutionError(
                "CREDENTIAL_HANDLE_REQUIRED",
                "Sandbox egress requires an opaque credential handle",
                user_action_required=True,
            )
        handle = ctx.credential_handle.get_secret_value()
        candidates = [
            binding for binding in self.resolver.config.bindings
            if binding.organization_id == ctx.organization_id
            and binding.handle.get_secret_value() == handle
        ]
        if len(candidates) != 1:
            raise CredentialResolutionError(
                "CREDENTIAL_HANDLE_INVALID",
                "Credential handle is not available for this organization",
                user_action_required=True,
            )
        binding = candidates[0]
        if binding.service_id != service_id:
            raise CredentialResolutionError(
                "CREDENTIAL_SCOPE_DENIED",
                "Credential handle is not authorized for this service",
                user_action_required=True,
            )
        requested = tuple(sorted({host.strip().lower().rstrip(".") for host in allowed_hosts if host.strip()}))
        bound = tuple(sorted(binding.allowed_hosts))
        if requested != bound:
            raise CredentialResolutionError(
                "CREDENTIAL_TARGET_DENIED",
                "Sandbox egress host policy must exactly match the credential binding host scope",
                user_action_required=True,
            )
        session = await self.resolver._mint_session(binding)
        return SandboxBrokerSession(
            proxyUrl=session.proxy_url,
            caCertificate=session.ca_certificate,
        )
