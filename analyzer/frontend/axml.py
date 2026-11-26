"""Minimal Android binary XML (AXML) reader for manifests and layouts."""

import struct
import zipfile

ATTR_NAMES = {
    0x01010003: "name",
    0x0101000E: "enabled",
    0x01010010: "exported",
    0x010100D0: "id",
    0x01010220: "inputType",
    0x0101026F: "onClick",
    0x0101015C: "password",
}


def _string_pool(data, start):
    count, _styles, flags, strings_start, _ = struct.unpack_from("<5I", data, start + 8)
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{count}I", data, start + 28)
    base = start + strings_start
    result = []
    for off in offsets:
        pos = base + off
        if utf8:
            n = data[pos]
            pos += 2 if n & 0x80 else 1
            n = data[pos]
            if n & 0x80:
                n = ((n & 0x7F) << 8) | data[pos + 1]
                pos += 2
            else:
                pos += 1
            result.append(data[pos : pos + n].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos)[0]
                pos += 2
            result.append(data[pos : pos + 2 * n].decode("utf-16-le", "replace"))
    return result


def parse(data):
    """Return a flat list of {tag, depth, attrs} for each element."""
    strings, res_ids, nodes = [], [], []
    depth = 0
    pos = 8
    while pos + 8 <= len(data):
        ctype, _hsize, size = struct.unpack_from("<HHI", data, pos)
        if size == 0:
            break
        if ctype == 0x0001:
            strings = _string_pool(data, pos)
        elif ctype == 0x0180:
            res_ids = list(struct.unpack_from(f"<{(size - 8) // 4}I", data, pos + 8))
        elif ctype == 0x0102:
            _ns, name, attr_start, attr_size, attr_count = struct.unpack_from(
                "<IIHHH", data, pos + 16
            )
            attrs = {}
            for i in range(attr_count):
                a = pos + 16 + attr_start + i * attr_size
                _ans, aname, raw, _sz, _r, dtype, value = struct.unpack_from("<IIIHBBI", data, a)
                key = strings[aname] if aname < len(strings) else ""
                if not key and aname < len(res_ids):
                    key = ATTR_NAMES.get(res_ids[aname], f"res_0x{res_ids[aname]:08x}")
                if raw != 0xFFFFFFFF and raw < len(strings):
                    val = strings[raw]
                elif dtype == 0x03:
                    val = strings[value]
                elif dtype == 0x12:
                    val = "true" if value else "false"
                elif dtype == 0x01:
                    val = f"@{value}"
                else:
                    val = str(value)
                attrs[key] = val
            nodes.append({"tag": strings[name], "depth": depth, "attrs": attrs})
            depth += 1
        elif ctype == 0x0103:
            depth -= 1
        pos += size
    return nodes


def read_apk_xml(apk):
    with zipfile.ZipFile(apk) as z:
        manifest = parse(z.read("AndroidManifest.xml"))
        layouts = {
            n: parse(z.read(n))
            for n in z.namelist()
            if n.startswith("res/layout") and n.endswith(".xml")
        }
    return manifest, layouts
