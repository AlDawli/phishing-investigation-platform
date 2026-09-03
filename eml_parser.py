"""
Parses a raw .eml file into a structured, JSON-serialisable dict that every
downstream module (auth, headers, URLs, attachments...) consumes.
"""
import email
import hashlib
import re
from email import policy
from email.utils import parseaddr, getaddresses
from typing import Any, Dict, List


class ParsedEmail:
    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self.raw_bytes = f.read()
        self.msg = email.message_from_bytes(self.raw_bytes, policy=policy.default)
        self.data: Dict[str, Any] = {}
        self._parse()

    # ------------------------------------------------------------------ #
    def _parse(self) -> None:
        msg = self.msg
        from_name, from_addr = parseaddr(msg.get("From", ""))
        reply_to_name, reply_to_addr = parseaddr(msg.get("Reply-To", ""))
        return_path_name, return_path_addr = parseaddr(msg.get("Return-Path", ""))

        self.data = {
            "message_id": msg.get("Message-ID", ""),
            "subject": msg.get("Subject", ""),
            "date": msg.get("Date", ""),
            "from": {"display_name": from_name, "address": from_addr},
            "reply_to": {"display_name": reply_to_name, "address": reply_to_addr},
            "return_path": return_path_addr,
            "to": [addr for _, addr in getaddresses([msg.get("To", "")])],
            "cc": [addr for _, addr in getaddresses([msg.get("Cc", "")])],
            "headers": {k: v for k, v in msg.items()},
            "received_chain": msg.get_all("Received", []) or [],
            "authentication_results": msg.get_all("Authentication-Results", []) or [],
            "dkim_signature": msg.get("DKIM-Signature", ""),
            "x_mailer": msg.get("X-Mailer", "") or msg.get("User-Agent", ""),
            "body_text": "",
            "body_html": "",
            "attachments": [],
            "raw_size_bytes": len(self.raw_bytes),
        }

        self._extract_body_and_attachments()

    # ------------------------------------------------------------------ #
    def _extract_body_and_attachments(self) -> None:
        for part in self.msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")

            if part.is_multipart():
                continue

            if "attachment" in disposition or (
                part.get_filename() and "inline" not in disposition
            ):
                self._add_attachment(part)
                continue

            if content_type == "text/plain" and not self.data["body_text"]:
                try:
                    self.data["body_text"] = part.get_content()
                except Exception:
                    self.data["body_text"] = str(part.get_payload(decode=True) or b"")
            elif content_type == "text/html" and not self.data["body_html"]:
                try:
                    self.data["body_html"] = part.get_content()
                except Exception:
                    self.data["body_html"] = str(part.get_payload(decode=True) or b"")

    def _add_attachment(self, part) -> None:
        filename = part.get_filename() or "unnamed_attachment"
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""

        self.data["attachments"].append(
            {
                "filename": filename,
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "md5": hashlib.md5(payload).hexdigest() if payload else "",
                "sha1": hashlib.sha1(payload).hexdigest() if payload else "",
                "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
                "_bytes": payload,  # stripped before final report export
            }
        )

    # ------------------------------------------------------------------ #
    def to_dict(self) -> Dict[str, Any]:
        """Returns parsed data without raw attachment bytes (safe to JSON-dump)."""
        clean = dict(self.data)
        clean["attachments"] = [
            {k: v for k, v in a.items() if k != "_bytes"} for a in self.data["attachments"]
        ]
        return clean
