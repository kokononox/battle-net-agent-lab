"""Bounded outgoing HTTP/1 capture. No requests are made by this module."""
import base64
import collections
import hashlib
import re
import struct

def valid_host(h):
    return isinstance(h,str) and len(h)<=253 and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",label) for label in h.split("."))
MAX_STREAM = 262144
MAX_TOTAL = 16 * 1024 * 1024
MAX_BODY = 65536
MAX_EXPORTED = 524288
MAX_REQUESTS = 64
SECRET_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie"}
START = re.compile(rb"(GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS|CONNECT) ([^\x00-\x20\x7f]{1,4096}) HTTP/1\.[01]$")

def parse_requests(data,redact_secrets=True):
    """No scanning/resync after malformed data; embedded HTTP strings aren't requests."""
    result = []
    pos = 0
    while pos < len(data) and len(result) < MAX_REQUESTS:
        end = data.find(b"\r\n\r\n", pos)
        if end < 0 or end - pos > 16384:
            return result, "incomplete_or_large_headers"
        lines = data[pos:end].split(b"\r\n")
        match = START.fullmatch(lines[0])
        if not match:
            return result, "not_http_request_at_boundary"
        headers = []
        mapping = collections.defaultdict(list)
        for line in lines[1:]:
            key, sep, value = line.partition(b":")
            if not sep or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
                return result, "invalid_headers"
            if any(x < 32 and x != 9 for x in value) or b"\x7f" in value:
                return result, "invalid_headers"
            key = key.decode("ascii").lower()
            value = value.strip().decode("latin1")
            mapping[key].append(value)
            headers.append([key, "[REDACTED]" if redact_secrets and key in SECRET_HEADERS else value])
        if len(mapping["host"]) != 1:
            return result, "invalid_host"
        host = mapping["host"][0].lower()
        if host.endswith(":80"):
            host = host[:-3]
        elif host.endswith(":443"):
            host = host[:-4]
        host = host.rstrip(".")
        body_start = end + 4
        complete = True
        transfer = ",".join(mapping["transfer-encoding"]).lower()
        if transfer and mapping["content-length"]:
            return result, "ambiguous_body_framing"
        if transfer:
            if transfer != "chunked":
                return result, "unsupported_transfer_encoding"
            pieces = []
            cur = body_start
            size_total = 0
            while True:
                line_end = data.find(b"\r\n", cur)
                if line_end < 0:
                    complete = False
                    break
                raw_size = data[cur:line_end].split(b";", 1)[0]
                if not re.fullmatch(rb"[0-9a-fA-F]{1,8}", raw_size):
                    return result, "invalid_chunk"
                size = int(raw_size, 16)
                cur = line_end + 2
                if size == 0:
                    if data[cur:cur+2] == b"\r\n":
                        cur += 2
                    else:
                        trailer_end = data.find(b"\r\n\r\n", cur)
                        if trailer_end < 0:
                            complete = False
                            break
                        # Trailers are not silently ignored or exported unredacted.
                        return result, "chunk_trailers_not_supported"
                    break
                if size_total + size > MAX_STREAM:
                    return result, "body_limit"
                if cur + size + 2 > len(data):
                    complete = False
                    break
                if data[cur+size:cur+size+2] != b"\r\n":
                    return result, "invalid_chunk"
                pieces.append(data[cur:cur+size])
                size_total += size
                cur += size + 2
            body = b"".join(pieces)
            next_pos = cur
            declared = None
        else:
            lengths = mapping["content-length"]
            if len(lengths) > 1 or (lengths and not re.fullmatch("[0-9]{1,10}", lengths[0])):
                return result, "invalid_content_length"
            declared = int(lengths[0]) if lengths else 0
            body = data[body_start:min(body_start + declared, len(data))]
            complete = len(body) == declared
            next_pos = body_start + len(body)
        if not valid_host(host):return result,"invalid_or_unsupported_host"
        if valid_host(host):
            sample = body[:MAX_BODY]
            result.append({
                "host": host, "method": match[1].decode(),
                "target": match[2].decode("latin1"),
                "headers": headers,
                "body_declared_bytes": declared,
                "body_observed_bytes": len(body),
                "body_complete": complete,
                "body_sample_truncated": len(sample) < len(body) or not complete,
                "body_sample_base64": base64.b64encode(sample).decode(),
                "body_sample_sha256": hashlib.sha256(sample).hexdigest(),
                "observed_body_sha256": hashlib.sha256(body).hexdigest(),
            })
        if not complete:
            return result, "incomplete_body"
        pos = next_pos
    return result, "request_limit" if pos < len(data) else "parsed_to_end"

