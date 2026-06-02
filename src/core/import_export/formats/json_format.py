import json
from typing import Any, Dict


class NativeJSONFormat:
    name = "encrypted_json"

    def serialize(self, data: Dict[str, Any]) -> str:
        return json.dumps(data, ensure_ascii=False, indent=2)

    def deserialize(self, raw_data: str) -> Dict[str, Any]:
        return json.loads(raw_data)

    def detect(self, data: Dict[str, Any]) -> bool:
        return data.get("cryptosafe_export") is True