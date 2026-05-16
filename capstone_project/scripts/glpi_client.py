import os
from pathlib import Path

import httpx
from dotenv import load_dotenv


ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")


class GLPIClient:
    def __init__(self):
        configured_url = os.getenv("GLPI_API_URL")
        if configured_url:
            self.api_url = configured_url.rstrip("/")
        else:
            glpi_port = os.getenv("GLPI_PORT", "8030")
            self.api_url = f"http://localhost:{glpi_port}/apirest.php"

        self.app_token = os.getenv("GLPI_APP_TOKEN")
        self.user_token = os.getenv("GLPI_USER_TOKEN")
        self.session_token = None
        self.timeout = 15.0

        if not self.app_token or not self.user_token:
            raise RuntimeError("GLPI_APP_TOKEN and GLPI_USER_TOKEN must be set in .env")

    def _auth_headers(self) -> dict:
        return {
            "App-Token": self.app_token,
            "Authorization": f"user_token {self.user_token}",
        }

    def _session_headers(self) -> dict:
        if not self.session_token:
            raise RuntimeError("GLPI session is not initialized. Call connect() first.")

        return {
            "App-Token": self.app_token,
            "Session-Token": self.session_token,
            "Content-Type": "application/json",
        }

    def connect(self) -> None:
        try:
            res = httpx.get(
                f"{self.api_url}/initSession",
                headers=self._auth_headers(),
                timeout=self.timeout,
            )
            if res.status_code != 200:
                print(f"[-] GLPI auth failed with {res.status_code}: {res.text}")
            res.raise_for_status()

            self.session_token = res.json().get("session_token")
            if not self.session_token:
                raise RuntimeError(f"GLPI did not return a session token: {res.text}")

            print("[+] GLPI Session Initialized.")
        except Exception as exc:
            print(f"[-] GLPI Connection Failed: {exc}")
            raise SystemExit(1)

    def get_computer_by_name(self, name: str) -> dict | None:
        res = httpx.get(
            f"{self.api_url}/Computer/",
            headers=self._session_headers(),
            params={"searchText[name]": name},
            timeout=self.timeout,
        )
        res.raise_for_status()

        data = res.json()
        if not isinstance(data, list):
            return None

        for item in data:
            if item.get("name") == name:
                return item

        return data[0] if data else None

    def create_computer(self, payload: dict) -> dict:
        res = httpx.post(
            f"{self.api_url}/Computer",
            headers=self._session_headers(),
            json={"input": payload},
            timeout=self.timeout,
        )
        if res.status_code not in (200, 201):
            print(f"[-] GLPI Computer creation failed with {res.status_code}: {res.text}")
        res.raise_for_status()
        return res.json()

    def update_computer(self, computer_id: int, payload: dict) -> dict:
        res = httpx.put(
            f"{self.api_url}/Computer/{computer_id}",
            headers=self._session_headers(),
            json={"input": payload},
            timeout=self.timeout,
        )
        if res.status_code != 200:
            print(f"[-] GLPI Computer update failed with {res.status_code}: {res.text}")
        res.raise_for_status()
        return res.json()

    def kill_session(self) -> None:
        if self.session_token:
            try:
                httpx.get(
                    f"{self.api_url}/killSession",
                    headers=self._session_headers(),
                    timeout=self.timeout,
                )
                print("[+] GLPI Session Terminated.")
            finally:
                self.session_token = None
