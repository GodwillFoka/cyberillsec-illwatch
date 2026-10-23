"""API factice pour tester le formulaire de démonstration du site (workflow « Site web »).

    python Website/scripts/mock_api.py DOSSIER_DU_SITE PORT

Sert le site construit avec ILLWATCH_SITE_DEMO_ENDPOINT=/api/v1/demo-requests et répond à
`POST /api/v1/demo-requests` comme l'application : 202 si le consentement est donné, 422 sinon,
429 au-delà de trois demandes (pour vérifier le message de limitation).
"""

import functools
import http.server
import json
import sys

received: list[dict[str, object]] = []


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - nom imposé par http.server
        if self.path != "/api/v1/demo-requests":
            self.send_error(404)
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        received.append(body)
        code = 429 if len(received) > 3 else (202 if body.get("consent") is True else 422)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "received"}).encode())

    def log_message(self, *args: object) -> None:
        pass


if __name__ == "__main__":
    handler = functools.partial(Handler, directory=sys.argv[1])
    http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[2])), handler).serve_forever()
