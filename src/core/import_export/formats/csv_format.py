import csv
import io
from typing import Dict, List


class CSVFormat:
    name = "csv"

    fieldnames = [
        "title",
        "username",
        "password",
        "url",
        "notes",
    ]

    def serialize(self, entries: List[Dict[str, str]]) -> str:
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=self.fieldnames,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()

        for entry in entries:
            writer.writerow(
                {
                    "title": entry.get("title", ""),
                    "username": entry.get("username", ""),
                    "password": entry.get("password", ""),
                    "url": entry.get("url", ""),
                    "notes": entry.get("notes", ""),
                }
            )

        return output.getvalue()

    def deserialize(self, raw_data: str) -> List[Dict[str, str]]:
        input_stream = io.StringIO(raw_data)
        reader = csv.DictReader(input_stream)
        entries = []

        for row in reader:
            entries.append(
                {
                    "title": row.get("title", ""),
                    "username": row.get("username", ""),
                    "password": row.get("password", ""),
                    "url": row.get("url", ""),
                    "notes": row.get("notes", ""),
                }
            )

        return entries