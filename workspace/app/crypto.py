"""密码学原语：规范 JSON 序列化、内容哈希、HMAC 委员签名。

- canonical_json：键排序、无空白、保留非 ASCII，保证跨端字节一致
- sha256_hex：SHA-256 十六进制
- hmac_hex：HMAC-SHA256（委员私钥对投票载荷签名）

注意：JSON 规范只有一种数字类型，并不区分整数与浮点。浏览器把
10.0 这类“整数取值的浮点”序列化为 10（JSON.parse(JSON.stringify(10.0)) === 10），
监管人员把页面下载的 JSON 原样保存再送入校验时，数值语义并未改变。
因此规范序列化对数值相等的数字给出相同字节，否则未改动的文件会被
误判为内容被改过。非整数取值的浮点（如 10.5）仍按其字面最短表示输出。
"""
from __future__ import annotations

import hashlib
import hmac
import json


def _number_text(value) -> str:
    # 整数取值的浮点与等价整数输出相同字节（10.0 与 10 都是 "10"），
    # 与浏览器/其他 JSON 实现对数字的处理一致：JS 对 |x| < 1e21 的整数用数字
    # 字面量、自 1e21 起用指数。范围外或非整数取值的浮点保留最短往返表示。
    if isinstance(value, int):
        return str(value)
    if value == int(value) and abs(value) < 1e21:
        return str(int(value))
    return json.dumps(value, ensure_ascii=False)


def _encode(obj) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, int):
        return _number_text(obj)
    if isinstance(obj, float):
        return _number_text(obj)
    if isinstance(obj, dict):
        return ("{" + ",".join(
            json.dumps(str(k), ensure_ascii=False) + ":" + _encode(v)
            for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))
        ) + "}")
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_encode(v) for v in obj) + "]"
    raise TypeError(f"无法规范序列化的类型：{type(obj).__name__}")


def canonical_json(obj) -> bytes:
    return _encode(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(obj) -> str:
    return sha256_hex(canonical_json(obj))


def hmac_hex(secret: str, data: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), data, hashlib.sha256).hexdigest()


def verify_hmac(secret: str, data: bytes, signature: str) -> bool:
    return hmac.compare_digest(hmac_hex(secret, data), signature or "")
