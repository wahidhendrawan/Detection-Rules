"""Unit tests for security hardening in deploy_rules.py and integration_test.py."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
import requests

# Add scripts to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from deploy_rules import _validate_url, _request_error, deploy_elastic, deploy_splunk, deploy_sentinel


# ============================================================================
# Tests for URL validation
# ============================================================================

class TestValidateUrl:
    """Test URL validation security constraints."""

    def test_https_only_by_default(self):
        """HTTPS is enforced by default."""
        with pytest.raises(ValueError, match="must use https"):
            _validate_url("http://localhost:8080")

    def test_https_accepted(self):
        """Valid HTTPS URLs are accepted."""
        result = _validate_url("https://elastic.example.com:9200")
        assert result == "https://elastic.example.com:9200"

    def test_http_allowed_with_opt_in(self):
        """HTTP is allowed only when explicitly enabled."""
        result = _validate_url("http://localhost:9200", allow_http=True)
        assert result == "http://localhost:9200"

    def test_trailing_slash_removed(self):
        """Trailing slashes are stripped."""
        result = _validate_url("https://example.com/", allow_http=False)
        assert result == "https://example.com"

    def test_invalid_scheme_rejected(self):
        """Schemes other than HTTP/HTTPS are rejected."""
        with pytest.raises(ValueError, match="must use https"):
            _validate_url("ftp://example.com")

    def test_missing_host_rejected(self):
        """URLs without a hostname are rejected."""
        with pytest.raises(ValueError, match="must include a host"):
            _validate_url("https://")

    def test_credentials_in_url_rejected(self):
        """URLs containing credentials are rejected."""
        with pytest.raises(ValueError, match="must not include credentials"):
            _validate_url("https://user:pass@example.com")

    def test_query_string_rejected(self):
        """URLs with query strings are rejected."""
        with pytest.raises(ValueError, match="must not include a query string"):
            _validate_url("https://example.com?key=value")

    def test_fragment_rejected(self):
        """URLs with fragments are rejected."""
        with pytest.raises(ValueError, match="must not include a query string or fragment"):
            _validate_url("https://example.com#section")

    def test_invalid_port_rejected(self):
        """URLs with invalid ports are rejected."""
        with pytest.raises(ValueError, match="invalid port"):
            _validate_url("https://example.com:notaport")

    def test_empty_url_rejected(self):
        """Empty strings are rejected."""
        with pytest.raises(ValueError, match="must be non-empty"):
            _validate_url("")

    def test_whitespace_only_url_rejected(self):
        """Whitespace-only strings are rejected."""
        with pytest.raises(ValueError, match="surrounding whitespace"):
            _validate_url("  ")


# ============================================================================
# Tests for error handling
# ============================================================================

class TestRequestError:
    """Test safe error classification."""

    def test_timeout_error_classified(self):
        """Timeout errors are classified without exposing details."""
        error = requests.Timeout("Connection timed out")
        result = _request_error(error)
        assert result == "Timeout"
        assert "timed out" not in result

    def test_connection_error_classified(self):
        """Connection errors are classified without exposing details."""
        error = requests.ConnectionError("Failed to connect")
        result = _request_error(error)
        assert result == "ConnectionError"
        assert "Failed to connect" not in result

    def test_request_exception_classified(self):
        """Generic request exceptions are classified."""
        error = requests.RequestException("Generic error")
        result = _request_error(error)
        assert result == "RequestException"


# ============================================================================
# Tests for deploy_elastic timeout and error handling
# ============================================================================

class TestDeployElasticSecurity:
    """Test Elastic deployment with security constraints."""

    @patch("deploy_rules.requests.post")
    def test_timeout_applied_to_request(self, mock_post, tmp_path):
        """Elastic deployment applies timeout to requests."""
        # Create a minimal NDJSON file
        rules_dir = tmp_path / "elastic"
        rules_dir.mkdir()
        (rules_dir / "test.ndjson").write_text('{"name":"test"}')

        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {"successCount": 1}
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = False
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {
            "ELASTIC_URL": "https://elastic.example.com",
            "ELASTIC_TOKEN": "test-token",
        }):
            from deploy_rules import deploy_elastic
            result = deploy_elastic(tmp_path)

        assert result is True
        # Verify timeout was passed
        assert mock_post.call_args.kwargs["timeout"] == 30

    @patch("deploy_rules.requests.post")
    def test_timeout_error_handled_gracefully(self, mock_post, tmp_path):
        """Timeout errors are handled without exposing details."""
        rules_dir = tmp_path / "elastic"
        rules_dir.mkdir()
        (rules_dir / "test.ndjson").write_text('{"name":"test"}')

        mock_post.side_effect = requests.Timeout("Connection timed out")

        with patch.dict(os.environ, {
            "ELASTIC_URL": "https://elastic.example.com",
            "ELASTIC_TOKEN": "test-token",
        }):
            from deploy_rules import deploy_elastic
            result = deploy_elastic(tmp_path)

        assert result is False

    @patch("deploy_rules.requests.post")
    def test_file_handle_closed_on_success(self, mock_post, tmp_path, capsys):
        """File handles are closed even on success."""
        rules_dir = tmp_path / "elastic"
        rules_dir.mkdir()
        test_file = rules_dir / "test.ndjson"
        test_file.write_text('{"name":"test"}')

        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {"successCount": 1}
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = False
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {
            "ELASTIC_URL": "https://elastic.example.com",
            "ELASTIC_TOKEN": "test-token",
        }):
            from deploy_rules import deploy_elastic
            deploy_elastic(tmp_path)

        # Verify the file is closed by checking it can be deleted
        test_file.unlink()
        assert not test_file.exists()


# ============================================================================
# Tests for deploy_splunk security
# ============================================================================

class TestDeploySplunkSecurity:
    """Test Splunk deployment with security constraints."""

    @patch("deploy_rules.requests.post")
    def test_verify_ssl_enabled_by_default(self, mock_post, tmp_path):
        """SSL verification is enabled by default."""
        rules_dir = tmp_path / "splunk"
        rules_dir.mkdir()
        (rules_dir / "test.spl").write_text("search index=main")

        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.status_code = 201
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = False
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {
            "SPLUNK_URL": "https://splunk.example.com",
            "SPLUNK_TOKEN": "test-token",
        }):
            from deploy_rules import deploy_splunk
            deploy_splunk(tmp_path)

        # Verify verify=True (SSL verification enabled)
        assert mock_post.call_args.kwargs["verify"] is True

    @patch("deploy_rules.requests.post")
    def test_verify_ssl_can_be_disabled_for_labs(self, mock_post, tmp_path):
        """SSL verification can be explicitly disabled for lab environments."""
        rules_dir = tmp_path / "splunk"
        rules_dir.mkdir()
        (rules_dir / "test.spl").write_text("search index=main")

        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.status_code = 201
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = False
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {
            "SPLUNK_URL": "https://splunk.example.com",
            "SPLUNK_TOKEN": "test-token",
            "SPLUNK_VERIFY_TLS": "false",
        }):
            from deploy_rules import deploy_splunk
            deploy_splunk(tmp_path)

        # Verify verify=False when explicitly disabled
        assert mock_post.call_args.kwargs["verify"] is False

    @patch("deploy_rules.requests.post")
    def test_timeout_applied_to_splunk(self, mock_post, tmp_path):
        """Splunk deployment applies timeout to requests."""
        rules_dir = tmp_path / "splunk"
        rules_dir.mkdir()
        (rules_dir / "test.spl").write_text("search index=main")

        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.status_code = 201
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = False
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {
            "SPLUNK_URL": "https://splunk.example.com",
            "SPLUNK_TOKEN": "test-token",
        }):
            from deploy_rules import deploy_splunk
            deploy_splunk(tmp_path)

        assert mock_post.call_args.kwargs["timeout"] == 30


# ============================================================================
# Tests for deploy_sentinel security
# ============================================================================

class TestDeploySentinelSecurity:
    """Test Sentinel deployment with security constraints."""

    @patch("deploy_rules.requests.put")
    @patch("deploy_rules.requests.post")
    def test_https_enforced_for_azure(self, mock_post, mock_put, tmp_path):
        """Sentinel deployment uses HTTPS for Azure endpoints."""
        rules_dir = tmp_path / "microsoft-sentinel"
        rules_dir.mkdir()
        (rules_dir / "test.kql").write_text("SecurityAlert | where TimeGenerated > ago(1d)")

        mock_token_response = MagicMock()
        mock_token_response.ok = True
        mock_token_response.json.return_value = {"access_token": "test-token"}
        mock_token_response.__enter__.return_value = mock_token_response
        mock_token_response.__exit__.return_value = False
        mock_post.return_value = mock_token_response

        mock_rule_response = MagicMock()
        mock_rule_response.ok = True
        mock_rule_response.__enter__.return_value = mock_rule_response
        mock_rule_response.__exit__.return_value = False
        mock_put.return_value = mock_rule_response

        with patch.dict(os.environ, {
            "SENTINEL_TENANT_ID": "tenant-123",
            "SENTINEL_CLIENT_ID": "client-123",
            "SENTINEL_CLIENT_SECRET": "secret-123",
            "SENTINEL_WORKSPACE_ID": "workspace-123",
            "AZURE_SUBSCRIPTION_ID": "sub-123",
            "SENTINEL_RESOURCE_GROUP": "rg-123",
        }):
            from deploy_rules import deploy_sentinel
            deploy_sentinel(tmp_path)

        # Verify auth endpoint is HTTPS
        assert mock_post.call_args[0][0].startswith("https://login.microsoftonline.com")

    @patch("deploy_rules.requests.post")
    def test_timeout_applied_to_sentinel_auth(self, mock_post, tmp_path):
        """Sentinel deployment applies timeout to authentication."""
        rules_dir = tmp_path / "microsoft-sentinel"
        rules_dir.mkdir()
        (rules_dir / "test.kql").write_text("SecurityAlert")

        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {"access_token": "token"}
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = False
        mock_post.return_value = mock_response

        with patch.dict(os.environ, {
            "SENTINEL_TENANT_ID": "tenant",
            "SENTINEL_CLIENT_ID": "client",
            "SENTINEL_CLIENT_SECRET": "secret",
            "SENTINEL_WORKSPACE_ID": "workspace",
            "AZURE_SUBSCRIPTION_ID": "sub",
            "SENTINEL_RESOURCE_GROUP": "rg",
        }):
            from deploy_rules import deploy_sentinel
            deploy_sentinel(tmp_path)

        # Verify timeout was applied to auth request
        assert mock_post.call_args.kwargs["timeout"] == 30


# ============================================================================
# Tests for integration_test.py cleanup and timeouts
# ============================================================================

class TestIntegrationTestCleanup:
    """Test that the integration test cleans up resources safely."""

    @patch("integration_test.requests.delete")
    @patch("integration_test.requests.post")
    @patch("integration_test.requests.put")
    def test_index_cleaned_up_on_success(self, mock_put, mock_post, mock_delete):
        """The test index is deleted after a successful run."""
        import integration_test

        mock_put.return_value = Mock(status_code=201)
        search_response = Mock(status_code=200)
        search_response.json.return_value = {"hits": {"total": {"value": 1}}}
        mock_post.return_value = search_response

        integration_test.main()

        # Cleanup delete must have been called with a timeout
        mock_delete.assert_called_once()
        assert mock_delete.call_args.kwargs["timeout"] == integration_test.REQUEST_TIMEOUT

    @patch("integration_test.requests.delete")
    @patch("integration_test.requests.put")
    def test_index_cleaned_up_on_failure(self, mock_put, mock_delete):
        """The test index is deleted even when setup fails."""
        import integration_test

        mock_put.return_value = Mock(status_code=500)

        result = integration_test.main()

        assert result == 1
        mock_delete.assert_called_once()

    @patch("integration_test.requests.delete")
    @patch("integration_test.requests.put")
    def test_cleanup_swallows_errors(self, mock_put, mock_delete):
        """Cleanup failures do not raise."""
        import integration_test

        mock_put.side_effect = requests.Timeout("timed out")
        mock_delete.side_effect = requests.ConnectionError("gone")

        # Should not raise despite cleanup error
        result = integration_test.main()
        assert result == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
