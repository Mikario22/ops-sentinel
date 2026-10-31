"""Optional LLM adapter tests: no outbound calls, only mocked transport."""
import io
import json
import unittest
from unittest.mock import patch

from ops_sentinel.narration import OpenAIResponsesNarrator


class FakeResponse:
    def __init__(self, body):
        self.stream = io.BytesIO(body)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, size=-1):
        return self.stream.read(size)


def mock_json_response(payload):
    return FakeResponse(json.dumps(payload).encode("utf-8"))


class NarrationTests(unittest.TestCase):
    def test_requires_explicit_opt_in_even_with_credentials(self):
        with self.assertRaises(PermissionError):
            OpenAIResponsesNarrator(model="example", api_key="not-real")

    def test_api_key_missing_rejected(self):
        with patch.dict("os.environ", {"OPENAI_API_KEY": ""}):
            with self.assertRaisesRegex(ValueError, "OPENAI_API_KEY"):
                OpenAIResponsesNarrator(allow_external_data_transfer=True, model="example")

    def test_model_name_validated(self):
        with self.assertRaisesRegex(ValueError, "model identifier"):
            OpenAIResponsesNarrator(allow_external_data_transfer=True, model="bad model", api_key="fake")

    def test_valid_mock_response_and_privacy_flags(self):
        response = {"status": "completed", "output": [
            {"type": "message", "content": [{"type": "output_text", "text": "Verify ticket manually."}]},
        ]}
        with patch("ops_sentinel.narration.request.urlopen", return_value=mock_json_response(response)) as fetch:
            adapter = OpenAIResponsesNarrator(allow_external_data_transfer=True, model="example", api_key="fake")
            result = adapter.summarize({"rule_id": "TEST", "evidence": []})
        self.assertEqual(result, "Verify ticket manually.")
        req = fetch.call_args.args[0]
        payload = json.loads(req.data)
        self.assertFalse(payload["store"])
        self.assertTrue("Never claim compromise" in payload["instructions"])
        self.assertEqual(fetch.call_args.kwargs["timeout"], 20)
        self.assertEqual(req.full_url, OpenAIResponsesNarrator.ENDPOINT)

    def test_incomplete_response_rejected(self):
        with patch("ops_sentinel.narration.request.urlopen", return_value=mock_json_response({"status": "incomplete"})):
            agent = OpenAIResponsesNarrator(allow_external_data_transfer=True, model="example", api_key="fake")
            with self.assertRaisesRegex(ValueError, "not completed"):
                agent.summarize({})

    def test_empty_output_rejected(self):
        with patch("ops_sentinel.narration.request.urlopen", return_value=mock_json_response({"status": "completed", "output": []})):
            agent = OpenAIResponsesNarrator(allow_external_data_transfer=True, model="example", api_key="fake")
            with self.assertRaisesRegex(ValueError, "no output text"):
                agent.summarize({})

    def test_large_response_rejected(self):
        with patch("ops_sentinel.narration.request.urlopen", return_value=FakeResponse(b"A" * 512_001)):
            agent = OpenAIResponsesNarrator(allow_external_data_transfer=True, model="example", api_key="fake")
            with self.assertRaisesRegex(ValueError, "exceeds allowed"):
                agent.summarize({})


if __name__ == "__main__":
    unittest.main()
