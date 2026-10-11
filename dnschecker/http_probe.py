"""
Подключение к серверу так же, как это делает консоль:
TCP → TLS с именем домена (SNI) и проверкой сертификата → HTTP-запрос.
"""

import socket
import ssl
import time

# How bad each result is: 0 = good, 4 = worst. Used to pick the best of several IPs.
PROBE_RANK = {"ok": 0, "forbidden": 1, "cert": 2, "tls_fail": 3, "no_http": 3, "tcp_fail": 4}


def probe(ip, host, mode, timeout, method="GET", path="/", port=None, ssl_context=None):
    """
    Возвращает словарь: state, code, ms, text, head.
      state: ok | forbidden | cert | tls_fail | no_http | tcp_fail
    port и ssl_context можно задать явно (используется в тестах).
    """
    port = port or (443 if mode == "https" else 80)
    start = time.perf_counter()
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except socket.timeout:
        return {"state": "tcp_fail", "text": f"порт {port} не отвечает (таймаут)"}
    except OSError as e:
        return {"state": "tcp_fail", "text": f"порт {port} недоступен: {e.strerror or e}"}

    try:
        if mode == "https":
            ctx = ssl_context or ssl.create_default_context()
            # SNI = the real domain name, exactly like the console sends it.
            try:
                sock = ctx.wrap_socket(sock, server_hostname=host)
            except ssl.SSLCertVerificationError as e:
                return {"state": "cert",
                        "text": f"сертификат не подходит (консоль такой не примет): {e.verify_message}"}
            except (ssl.SSLError, OSError) as e:
                return {"state": "tls_fail",
                        "text": f"TLS-соединение оборвалось — похоже на блокировку по имени домена ({e})"}

        body = "{}" if method == "POST" else ""
        request = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DNS-Checker\r\nAccept: */*\r\n"
                   + ("Content-Type: application/json\r\n" if body else "")
                   + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}")
        sock.sendall(request.encode())
        data = b""
        try:
            while len(data) < 4096:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass  # the server closed the connection: use what we already got
    finally:
        sock.close()

    return parse_response(data, (time.perf_counter() - start) * 1000)


def parse_response(data, ms):
    """Разбирает начало HTTP-ответа: код и первые строки заголовков."""
    head = data.decode("latin-1", errors="replace").replace("\r\n", "\n")
    first_line = head.split("\n", 1)[0]
    parts = first_line.split()
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        return {"state": "no_http", "ms": ms,
                "text": "соединение есть, но сервер ничего внятного не ответил", "head": head[:600]}
    code = int(parts[1])
    state = "forbidden" if code in (403, 451) else "ok"
    return {"state": state, "code": code, "ms": ms, "text": first_line, "head": head[:600]}
