from unittest.mock import MagicMock, patch

import httpx
import pytest

from firellm.delivery import HTTPPromptDeliveryAdapter, PromptDeliveryError


def test_http_adapter_auth_bearer() -> None:
    adapter = HTTPPromptDeliveryAdapter(
        target_url="http://mock.endpoint",
        auth={"type": "bearer", "token": "test-token"}
    )
    assert adapter.headers["Authorization"] == "Bearer test-token"
    assert adapter.headers["Content-Type"] == "application/json"


def test_http_adapter_auth_basic() -> None:
    adapter = HTTPPromptDeliveryAdapter(
        target_url="http://mock.endpoint",
        auth={"type": "basic", "username": "admin", "password": "password123"}
    )
    # admin:password123 base64 encoded is YWRtaW46cGFzc3dvcmQxMjM=
    assert adapter.headers["Authorization"] == "Basic YWRtaW46cGFzc3dvcmQxMjM="


def test_http_adapter_auth_apikey() -> None:
    adapter = HTTPPromptDeliveryAdapter(
        target_url="http://mock.endpoint",
        auth={"type": "apikey", "key_name": "X-API-Key", "key_value": "secret-value"}
    )
    assert adapter.headers["X-API-Key"] == "secret-value"


@patch("httpx.Client")
def test_http_adapter_sends_correct_payload(mock_client_class: MagicMock) -> None:
    mock_client = MagicMock()
    mock_client_class.return_value.__enter__.return_value = mock_client
    
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.is_success = True
    mock_response.text = "mocked llm response"
    mock_client.post.return_value = mock_response

    adapter = HTTPPromptDeliveryAdapter(target_url="http://mock.endpoint", headers={"X-Custom": "val"})
    res = adapter.send("hello test prompt")

    assert res == "mocked llm response"
    mock_client.post.assert_called_once_with(
        "http://mock.endpoint",
        json={"prompt": "hello test prompt"},
        headers={"Content-Type": "application/json", "X-Custom": "val"}
    )


@patch("time.sleep")
@patch("httpx.Client")
def test_http_adapter_retries_on_500_and_succeeds(mock_client_class: MagicMock, mock_sleep: MagicMock) -> None:
    mock_client = MagicMock()
    mock_client_class.return_value.__enter__.return_value = mock_client
    
    # First call returns 500 Internal Server Error, second call returns 200 OK
    resp_500 = MagicMock(spec=httpx.Response)
    resp_500.is_success = False
    resp_500.status_code = 500
    resp_500.text = "Internal error"
    
    resp_200 = MagicMock(spec=httpx.Response)
    resp_200.is_success = True
    resp_200.status_code = 200
    resp_200.text = "recovered response"

    mock_client.post.side_effect = [resp_500, resp_200]

    adapter = HTTPPromptDeliveryAdapter(target_url="http://mock.endpoint", max_retries=2, backoff_factor=1.0)
    res = adapter.send("test query")

    assert res == "recovered response"
    assert mock_client.post.call_count == 2
    mock_sleep.assert_called_once_with(1.0)  # first backoff: 1.0 * (2 ** 0) = 1.0


@patch("time.sleep")
@patch("httpx.Client")
def test_http_adapter_raises_after_max_retries(mock_client_class: MagicMock, mock_sleep: MagicMock) -> None:
    mock_client = MagicMock()
    mock_client_class.return_value.__enter__.return_value = mock_client
    
    resp_429 = MagicMock(spec=httpx.Response)
    resp_429.is_success = False
    resp_429.status_code = 429
    resp_429.text = "Too many requests"
    mock_client.post.return_value = resp_429

    adapter = HTTPPromptDeliveryAdapter(target_url="http://mock.endpoint", max_retries=3, backoff_factor=2.0)
    
    with pytest.raises(PromptDeliveryError) as exc_info:
        adapter.send("test query")

    assert "HTTP delivery failed after 3 retries: HTTP error 429" in str(exc_info.value)
    assert mock_client.post.call_count == 4  # 1 initial + 3 retries
    assert mock_sleep.call_count == 3
    # Wait times: 2.0 * 1 = 2.0, 2.0 * 2 = 4.0, 2.0 * 4 = 8.0
    mock_sleep.assert_any_call(2.0)
    mock_sleep.assert_any_call(4.0)
    mock_sleep.assert_any_call(8.0)


@patch("time.sleep")
@patch("httpx.Client")
def test_http_adapter_non_retryable_client_error(mock_client_class: MagicMock, mock_sleep: MagicMock) -> None:
    mock_client = MagicMock()
    mock_client_class.return_value.__enter__.return_value = mock_client
    
    resp_401 = MagicMock(spec=httpx.Response)
    resp_401.is_success = False
    resp_401.status_code = 401
    resp_401.text = "Unauthorized access"
    mock_client.post.return_value = resp_401

    adapter = HTTPPromptDeliveryAdapter(target_url="http://mock.endpoint", max_retries=3)
    
    with pytest.raises(PromptDeliveryError) as exc_info:
        adapter.send("test query")

    assert "non-retryable status 401" in str(exc_info.value)
    assert mock_client.post.call_count == 1  # Fails immediately
    assert mock_sleep.call_count == 0


@patch("time.sleep")
@patch("httpx.Client")
def test_http_adapter_retries_on_network_error(mock_client_class: MagicMock, mock_sleep: MagicMock) -> None:
    mock_client = MagicMock()
    mock_client_class.return_value.__enter__.return_value = mock_client
    
    # 2 network errors, then success
    resp_200 = MagicMock(spec=httpx.Response)
    resp_200.is_success = True
    resp_200.status_code = 200
    resp_200.text = "success after connection loss"
    
    mock_client.post.side_effect = [
        httpx.ConnectError("Connection timed out"),
        httpx.NetworkError("Host unreachable"),
        resp_200
    ]

    adapter = HTTPPromptDeliveryAdapter(target_url="http://mock.endpoint", max_retries=3, backoff_factor=1.0)
    res = adapter.send("test query")

    assert res == "success after connection loss"
    assert mock_client.post.call_count == 3
    assert mock_sleep.call_count == 2
