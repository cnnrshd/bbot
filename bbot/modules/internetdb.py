from bbot.modules.base import BaseModule


class internetdb(BaseModule):
    """
    Query IP in Shodan's InternetDB tool, returning open ports, discovered technologies, findings, and DNS names
    API reference: https://internetdb.shodan.io/docs
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = ["TECHNOLOGY", "FINDING", "OPEN_TCP_PORT", "DNS_NAME"]
    flags = ["passive", "safe", "portscan"]
    meta = {
        "description": "Query Shodan's internet_db for open ports, hostnames, and potential vulnerabilities",
        "auth_required": False,
    }
    base_url = "https://internetdb.shodan.io"
    scope_distance_modifier = 1

    def _parse_response(self, data: dict, event):
        """Handles emiting events from returned JSON"""
        data: dict  # has keys: cpes, hostnames, ip, ports, tags, vulns
        # ip is a string, ports is a list of ports, the rest is a list of strings
        for hostname in data.get("hostnames", []):
            self.emit_event(hostname, "DNS_NAME", source=event)
        # Decrease scope distance for ports since ports are directly connected to the host (target?)
        event.scope_distance = event.scope_distance - 1
        for cpe in data.get("cpes", []):
            self.emit_event({"technology": cpe, "host": str(event.host), "type": "cpe"}, "TECHNOLOGY", source=event)
        for port in data.get("ports", []):
            self.emit_event(self.helpers.make_netloc(event.data, port), "OPEN_TCP_PORT", source=event)
        for vuln in data.get("vulns", []):
            self.emit_event(
                {"description": f"Shodan reported verified CVE {vuln}", "host": str(event.host), "type": "cve"},
                "FINDING",
                source=event,
            )

    async def handle_event(self, event):
        url = f"{self.base_url}/{event.data}"
        r = await self.helpers.request(url)
        if r is None:
            self.debug(f"No response for {event.data}")
            return
        try:
            data = r.json()
        except Exception:
            return
        if data:
            if r.status_code == 200:
                self._parse_response(data=data, event=event)
            elif r.status_code == 404:
                self.debug(f"No results for {event.data}")
            else:
                self.error(f"Shodan InternetDB Error for {event.data}: {r.status_code}")
                self.debug(f"{r.text}")
