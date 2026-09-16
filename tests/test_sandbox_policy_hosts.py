from pydantic import ValidationError

from universal_connection_service.sandbox_policy import SandboxCapabilityProfile


def test_sandbox_egress_rejects_wildcard_and_ip_hosts():
    for host in ("*", "*.example.com", "127.0.0.1", "8.8.8.8", "::1"):
        try:
            SandboxCapabilityProfile(egressHosts=(host,), brokeredCredentials=True)
            assert False, f"expected invalid sandbox egress host: {host}"
        except ValidationError:
            pass


def test_sandbox_egress_accepts_concrete_dns_hosts():
    profile = SandboxCapabilityProfile(
        egressHosts=("API.Example.COM.", "auth.example.com"),
        brokeredCredentials=True,
    )
    assert profile.egress_hosts == ("api.example.com", "auth.example.com")
