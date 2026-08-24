#!/usr/bin/env python3
"""Diagnostic: log EVERY shadow message, with full payloads and timestamps.

Read-only unless --write is passed. Instrumentation only - this does not
modify the library. It exists to show WHICH component boundary fails.

  python shadow_trace.py --watch 60          # observe the vendor app
  python shadow_trace.py --write light=1     # observe our own write
"""
import argparse
import asyncio
import getpass
import json
import os
import sys
import time
from datetime import UTC, datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

import aiohttp
import paho.mqtt.client as mqtt
from pyzephyrconnect import const
from pyzephyrconnect.api import ZephyrApi
from pyzephyrconnect.auth import ZephyrAuth
from pyzephyrconnect.presign import build_presigned_url

T0 = time.monotonic()
def stamp() -> str:
    return f"[{time.monotonic()-T0:6.2f}s]"

async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--watch", type=int, default=45)
    ap.add_argument("--write", help="field=value, published as state.desired")
    ap.add_argument("--write-reported", help="field=value, published as state.REPORTED")
    ap.add_argument("--clear-desired", action="store_true",
                    help="publish state.desired=null to clear stuck desired pollution")
    args = ap.parse_args()

    user = os.environ.get("ZEPHYR_USER") or input("email: ")
    pw = os.environ.get("ZEPHYR_PASS") or getpass.getpass("password: ")

    auth = ZephyrAuth(user, pw)
    await auth.authenticate()
    await auth.attach_policy()
    print(f"{stamp()} auth ok, policy attached")

    async with aiohttp.ClientSession() as session:
        devices = await ZephyrApi(session).get_own_devices(auth.id_token)
    thing = devices[0]["thingName"]
    base = f"$aws/things/{thing}/shadow"
    print(f"{stamp()} thing resolved (redacted), base=$aws/things/<thing>/shadow")

    creds = auth.credentials
    url = build_presigned_url(
        creds.access_key, creds.secret_key, creds.session_token,
        endpoint=const.IOT_ENDPOINT, region=const.REGION, now=datetime.now(UTC))
    from urllib.parse import urlsplit
    parts = urlsplit(url)

    loop = asyncio.get_running_loop()
    connected = asyncio.Event()
    seen: list = []

    def on_connect(c, u, f, rc, props=None):
        loop.call_soon_threadsafe(connected.set)

    def on_sub(c, u, mid, rcs, props):
        for rc in rcs:
            ok = not getattr(rc, "is_failure", False)
            print(f"{stamp()} SUBACK mid={mid} granted={'OK' if ok else 'DENIED(128)'}")

    def on_msg(c, u, m):
        leaf = m.topic.replace(base, "<shadow>")
        try:
            payload = json.loads(m.payload)
            body = json.dumps(payload, indent=2, sort_keys=True)
        except Exception:
            body = repr(m.payload[:400])
        line = f"{stamp()} <<< {leaf}\n{body}"
        loop.call_soon_threadsafe(lambda: (print(line), seen.append(leaf)))

    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                         client_id=auth.mqtt_client_id + "-trace",
                         transport="websockets", protocol=mqtt.MQTTv311)
    client.ws_set_options(path=f"{parts.path}?{parts.query}")
    client.tls_set()
    client.on_connect, client.on_subscribe, client.on_message = on_connect, on_sub, on_msg
    client.connect_async(const.IOT_ENDPOINT, 443, keepalive=30)
    client.loop_start()
    await asyncio.wait_for(connected.wait(), 20)
    print(f"{stamp()} connected")

    # Wildcard first: catches ANY topic, including ones we never anticipated.
    for topic in (f"{base}/#",
                  f"{base}/get/accepted", f"{base}/get/rejected",
                  f"{base}/update/accepted", f"{base}/update/rejected",
                  f"{base}/update/delta", f"{base}/update/documents"):
        client.subscribe(topic, qos=1)
        print(f"{stamp()} >>> SUBSCRIBE {topic.replace(base,'<shadow>')}")
        await asyncio.sleep(0.4)

    print(f"\n{stamp()} --- baseline get ---")
    client.publish(f"{base}/get", "{}", qos=1)
    await asyncio.sleep(3)

    if args.clear_desired:
        print(f"\n{stamp()} --- CLEARING state.desired (removes stuck deltas) ---")
        info = client.publish(f"{base}/update",
                              json.dumps({"state": {"desired": None}}), qos=1)
        info.wait_for_publish(timeout=10)
        print(f"{stamp()} PUBACK rc={info.rc}")
        await asyncio.sleep(3)

    if args.write or args.write_reported:
        raw = args.write or args.write_reported
        field, _, val = raw.partition("=")
        block = "desired" if args.write else "reported"
        payload = {"state": {block: {field.strip(): int(val)}}}
        print(f"\n{stamp()} --- PUBLISHING to <shadow>/update ---")
        print(json.dumps(payload))
        info = client.publish(f"{base}/update", json.dumps(payload), qos=1)
        info.wait_for_publish(timeout=10)
        print(f"{stamp()} PUBACK received, rc={info.rc}, is_published={info.is_published()}")
        print(f"{stamp()} watching {args.watch}s for the response...\n")
    else:
        print(f"\n{stamp()} >>> NOW toggle the light/fan IN THE VENDOR APP <<<")
        print(f"{stamp()} watching {args.watch}s...\n")

    await asyncio.sleep(args.watch)

    print(f"\n{stamp()} === SUMMARY ===")
    if seen:
        from collections import Counter
        for topic, n in Counter(seen).items():
            print(f"  {n:3d} x {topic}")
    else:
        print("  NO MESSAGES RECEIVED AT ALL")
    client.loop_stop()
    client.disconnect()
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
