"""Bind a WoW EU target to official HTTPS tables and checksum-verified configs.

No game paths, process access, game writes or bulk asset downloads.
"""
import hashlib
import re
import threading
from dataclasses import dataclass
from urllib.parse import urlsplit, parse_qsl
import repair_core as core

VERSIONS = "https://us.version.battle.net/v2/products/wow/versions"
CDNS = "https://us.version.battle.net/v2/products/wow/cdns"
CAP = 4 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{32}")


class MetadataError(core.RepairError):
    pass


def table(data):
    if not isinstance(data, bytes) or len(data) > CAP:
        raise MetadataError("metadata_table_size")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError:
        raise MetadataError("metadata_table_encoding") from None
    lines = [s.strip() for s in text.splitlines()
             if s.strip() and not s.lstrip().startswith("#")]
    if len(lines) < 2 or len(lines) > 10000:
        raise MetadataError("metadata_table_rows")
    cols = [c.split("!", 1)[0] for c in lines[0].split("|")]
    if not all(re.fullmatch("[A-Za-z][A-Za-z0-9_ ]{0,63}", c) for c in cols):
        raise MetadataError("metadata_table_columns")
    if len(set(cols)) != len(cols):
        raise MetadataError("metadata_duplicate_columns")
    rows = []
    for line in lines[1:]:
        values = line.split("|")
        if len(values) != len(cols):
            raise MetadataError("metadata_table_row_width")
        rows.append(dict(zip(cols, values)))
    return rows


def one_eu(rows, field):
    matches = [r for r in rows if r.get(field) == "eu"]
    if len(matches) != 1:
        raise MetadataError("expected_one_eu_row")
    return matches[0]


def key(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise MetadataError("invalid_metadata_key")
    return value


def fetch_small(transport, url, cancel):
    core.check(cancel)
    with transport.open(url, {}) as response:
        if (response.status != 200 or response.geturl() != url
                or response.headers.get("Content-Range")
                or response.headers.get("Content-Encoding", "identity").lower()
                not in ("", "identity")):
            raise MetadataError("metadata_response_invalid")
        length = response.headers.get("Content-Length")
        if length is not None and (
                not re.fullmatch("[0-9]+", length) or int(length) > CAP):
            raise MetadataError("metadata_response_size")
        blocks, total = [], 0
        while True:
            core.check(cancel)
            block = response.read(min(65536, CAP + 1 - total))
            if not block:
                break
            blocks.append(block)
            total += len(block)
            if total > CAP:
                raise MetadataError("metadata_response_size")
        if length is not None and total != int(length):
            raise MetadataError("metadata_truncated")
    core.check(cancel)
    return b"".join(blocks)


def config(data, expected):
    key(expected)
    if len(data) > CAP or hashlib.md5(data).hexdigest() != expected:
        raise MetadataError("config_checksum_mismatch")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError:
        raise MetadataError("config_text_encoding") from None
    result = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            raise MetadataError("unsupported_config_line")
        name, value = line.split("=", 1)
        name = name.strip()
        if not re.fullmatch("[A-Za-z0-9_-]{1,80}", name) or name in result:
            raise MetadataError("config_duplicate_or_invalid_field")
        result[name] = value.split()
    return result


def origins(cdns):
    if cdns.get("Path") != "tpr/wow":
        raise MetadataError("unexpected_product_cdn_path")
    result = []
    # Only HTTPS Servers explicitly advertised by the official EU table.
    # Hosts (legacy HTTP) and arbitrary user-provided origins are NOT fallbacks.
    for server in cdns.get("Servers", "").split():
        try:
            p = urlsplit(server)
            host = p.hostname or ""
            port = p.port
            # Official Servers rows use these origin-selection hints, e.g.
            # /?maxhosts=8&fallback=1. They are not object URL query parameters.
            hints = parse_qsl(p.query, keep_blank_values=True, strict_parsing=True)
        except ValueError:
            continue
        if len(dict(hints)) != len(hints) or any(
                not ((k == "maxhosts" and re.fullmatch("[0-9]{1,2}", v)
                      and 1 <= int(v) <= 64) or
                     (k == "fallback" and v in ("0", "1")))
                for k, v in hints):
            continue
        if (p.scheme == "https" and not p.username and not p.password
                and port in (None, 443) and p.path in ("", "/")
                and not p.fragment
                and re.fullmatch("[a-zA-Z0-9.-]+", host)
                and "." in host and not host.replace(".", "").isdigit()
                and not host.lower().endswith((".local", ".localhost"))
                and host.lower() != "localhost"):
            origin = "https://" + host.lower()
            if origin not in result:
                result.append(origin)
    if not result:
        raise MetadataError("no_supported_official_eu_https_origin")
    return tuple(result)


@dataclass(frozen=True)
class Target:
    version: str
    build_id: int
    build_config: str
    cdn_config: str
    origins: tuple

    def identity(self):
        return self.version, self.build_id, self.build_config, self.cdn_config


def discover(transport, cancel=None):
    cancel = cancel or threading.Event()
    v = one_eu(table(fetch_small(transport, VERSIONS, cancel)), "Region")
    c = one_eu(table(fetch_small(transport, CDNS, cancel)), "Name")
    version = v.get("VersionsName", "")
    build = v.get("BuildId", "")
    if (not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", version)
            or not re.fullmatch("[0-9]{1,10}", build)
            or int(build) != int(version.rsplit(".", 1)[1])):
        raise MetadataError("version_build_id_conflict")
    return Target(version, int(build), key(v.get("BuildConfig")),
                  key(v.get("CDNConfig")), origins(c))


def config_url(origin, config_key):
    key(config_key)
    return origin + "/tpr/wow/config/" + config_key[:2] + "/" + config_key[2:4] + "/" + config_key


def load_configs(target, transport, cancel=None):
    cancel = cancel or threading.Event()
    origin = target.origins[0]
    raw_build = fetch_small(transport, config_url(origin, target.build_config), cancel)
    build = config(raw_build, target.build_config)
    raw_cdn = fetch_small(transport, config_url(origin, target.cdn_config), cancel)
    cdn = config(raw_cdn, target.cdn_config)
    expected = "WOW-" + str(target.build_id) + "patch" + target.version.rsplit(".", 1)[0] + "_Retail"
    if build.get("build-uid") != ["wow"] or build.get("build-name") != [expected]:
        raise MetadataError("retail_target_build_identity_mismatch")
    if "builds" in cdn:
        if any(not HEX.fullmatch(s) for s in cdn["builds"]):
            raise MetadataError("cdn_build_list_invalid")
        if target.build_config not in cdn["builds"]:
            raise MetadataError("cdn_build_config_conflict")
    return build, cdn


def download_spec(target, build):
    return manifest_spec(target, build, "download", 256 * 1024**2)


def manifest_spec(target, build, name, limit=512 * 1024**2):
    if name not in ("download", "encoding"):
        raise MetadataError("unsupported_manifest_name")
    keys = build.get(name, [])
    sizes = build.get(name + "-size", [])
    if len(keys) != 2:
        raise MetadataError(name + "_full_key_pair_required_encoding_lookup_not_implemented")
    if (len(sizes) != 2 or any(not re.fullmatch("[0-9]{1,12}", s) for s in sizes)):
        raise MetadataError(name + "_decoded_encoded_size_pair_required")
    ck, ek = (key(s) for s in keys)
    ds, es = (int(s) for s in sizes)
    if not 0 < ds <= limit or not 0 < es <= min(limit, core.decoded_payload.MAX_ENCODED):
        raise MetadataError(name + "_metadata_size_limit")
    # Known metadata object, not a guess that arbitrary game assets are loose.
    url = target.origins[0] + "/tpr/wow/data/" + ek[:2] + "/" + ek[2:4] + "/" + ek
    return core.Spec("_retail_/Metadata/" + name.upper(), ck, ds, ek, es, url).validate()