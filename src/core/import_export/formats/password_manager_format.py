from typing import Any, Dict, List


class PasswordManagerFormat:
    name = "password_manager"

    def to_bitwarden_json(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        items = []

        for entry in entries:
            uris = []

            if entry.get("url"):
                uris.append(
                    {
                        "uri": entry.get("url", ""),
                    }
                )

            items.append(
                {
                    "type": 1,
                    "name": entry.get("title", "Untitled"),
                    "notes": entry.get("notes", ""),
                    "login": {
                        "username": entry.get("username", ""),
                        "password": entry.get("password", ""),
                        "uris": uris,
                    },
                }
            )

        return {
            "encrypted": False,
            "items": items,
        }

    def from_bitwarden_json(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        entries = []

        for item in data.get("items", []):
            login = item.get("login", {})
            uris = login.get("uris", [])

            url = ""
            if uris and isinstance(uris, list):
                url = uris[0].get("uri", "")

            entries.append(
                {
                    "title": item.get("name", "Untitled"),
                    "username": login.get("username", ""),
                    "password": login.get("password", ""),
                    "url": url,
                    "notes": item.get("notes", ""),
                }
            )

        return entries