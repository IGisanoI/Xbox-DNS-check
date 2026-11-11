"""
Подключение к серверу так же, как это делает консоль:
TCP → TLS с именем домена (SNI) и проверкой сертификата → HTTP-запрос.
"""

import json
import socket
import ssl
import time

# How bad each result is: 0 = good, 4 = worst. Used to pick the best of several IPs.
PROBE_RANK = {
    "ok": 0, "forbidden": 1, "redirect": 2, "unexpected": 2, "server_error": 2,
    "cert": 2, "tls_fail": 3, "no_http": 3, "tcp_fail": 4,
}


def probe(ip, host, mode, timeout, method="GET", path="/", headers=None, payload=None,
          expected=None, port=None, ssl_context=None):
    """
    Возвращает словарь: state, category, code, ms, text, head, body.
    headers/payload/expected описываются для каждого домена в consoles.json.
    port и ssl_context можно задать явно (используется в тестах).
    """
    port = port or (443 if mode == "https" else 80)
    clean_headers = []
    for key, value in (headers or {}).items():
        key, value = str(key), str(value)
        if ":" in key or "\r" in key + value or "\n" in key + value:
            raise ValueError("недопустимый HTTP-заголовок в consoles.json")
        clean_headers.append((key, value))
    start = time.perf_counter()
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except socket.timeout:
        return {"state": "tcp_fail", "category": "unreachable",
                "text": f"порт {port} не отвечает (таймаут)"}
    except OSError as e:
        return {"state": "tcp_fail", "category": "unreachable",
                "text": f"порт {port} недоступен: {e.strerror or e}"}

    try:
        if mode == "https":
            ctx = ssl_context or ssl.create_default_context()
            # SNI = the real domain name, exactly like the console sends it.
            try:
                sock = ctx.wrap_socket(sock, server_hostname=host)
            except ssl.SSLCertVerificationError as e:
                return {"state": "cert", "category": "invalid_certificate",
                        "text": f"сертификат не подходит (консоль такой не примет): {e.verify_message}"}
            except TimeoutError:
                return {"state": "tls_fail", "category": "unreachable",
                        "text": f"TLS не ответил за {timeout} с — похоже на блокировку по имени домена "
                                "(или сервер очень медленный)"}
            except (ssl.SSLError, OSError) as e:
                return {"state": "tls_fail", "category": "unreachable",
                        "text": f"TLS-соединение оборвалось — похоже на блокировку по имени домена ({e})"}

        body = ""
        if method == "POST":
            body = json.dumps(payload if payload is not None else {}, ensure_ascii=False,
                              separators=(",", ":"))
        extra_headers = "".join(f"{key}: {value}\r\n" for key, value in clean_headers)
        request = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DNS-Checker\r\n"
                   f"Accept: */*\r\n{extra_headers}"
                   + ("Content-Type: application/json\r\n" if body else "")
                   + (f"Content-Length: {len(body.encode())}\r\n" if body or method == "POST" else "")
                   + f"Connection: close\r\n\r\n{body}")
        try:
            sock.sendall(request.encode())
        except OSError as e:
            return {"state": "no_http", "category": "unreachable",
                    "text": f"не удалось отправить HTTP-запрос: {e}"}
        data = b""
        try:
            while len(data) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass  # the server closed the connection: use what we already got
    finally:
        sock.close()

    return parse_response(data, (time.perf_counter() - start) * 1000, expected)


def parse_response(data, ms, expected=None):
    """Разбирает HTTP-ответ и отделяет достижимость от успеха входа в Xbox."""
    text = data.decode("latin-1", errors="replace")
    head, _separator, body = text.partition("\r\n\r\n")
    first_line = head.split("\r\n", 1)[0]
    parts = first_line.split()
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        return {"state": "no_http", "category": "invalid_response", "ms": ms,
                "text": "соединение есть, но сервер ничего внятного не ответил",
                "head": head[:600], "body": ""}
    code = int(parts[1])
    expected_codes = set(expected) if expected else set(range(200, 300)) | {400, 401}
    if code in (403, 451):
        state, category = "forbidden", "blocked"
    elif 500 <= code <= 599:
        state, category = "server_error", "server_error"
    elif code in expected_codes:
        state = "ok"
        category = "redirect" if 300 <= code <= 399 else "expected"
    elif 300 <= code <= 399:
        state, category = "redirect", "redirect"
    else:
        state, category = "unexpected", "unexpected"
    return {"state": state, "category": category, "code": code, "ms": ms,
            "text": first_line, "head": head[:600], "body": body[:600]}
