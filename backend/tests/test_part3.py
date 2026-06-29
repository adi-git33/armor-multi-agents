"""
Part 3 Test  |  Message Bus
=============================
Checks:
  1. Basic pub/sub   — message reaches the right subscriber
  2. Lamport clocks  — strictly increasing across publishes
  3. Deduplication   — same (sender, seq) delivered only once
  4. FIFO ordering   — messages arrive in publish order
  5. Topic isolation — publishing to one topic doesn't reach another's subscriber
  6. Multi-subscriber — two subscribers on the same topic both receive
  7. All performatives accepted — INFORM, BID, FAILURE, NOT_UNDERSTOOD, etc.
  8. Bus stats       — published / delivered / dropped counts are consistent
"""

import asyncio

from core.messages import Message, Performative, Topic
from bus.message_bus import MessageBus


def _msg(perf, sender, topic, content, seq=0, **kw) -> Message:
    return Message(performative=perf, sender=sender,
                   topic=topic, content=content, seq=seq, **kw)


async def main() -> None:
    print("=" * 65)
    print("  Part 3 Test  |  Message Bus")
    print("=" * 65)

    all_ok = True

    def check(label: str, ok: bool, detail: str = "") -> None:
        nonlocal all_ok
        mark = "PASS" if ok else "FAIL"
        print(f"\n  [{mark}] {label}")
        if detail:
            print(f"         {detail}")
        if not ok:
            all_ok = False

    bus = MessageBus()
    await bus.start()

    # ── 1. Basic pub/sub ──────────────────────────────────────────────
    got_alerts: list[Message] = []

    async def on_alert(m: Message):
        got_alerts.append(m)

    bus.subscribe(Topic.ALERTS, on_alert)

    await bus.publish(_msg(
        Performative.INFORM, "TMA:1", Topic.ALERTS,
        {"anomaly_type": "VOLUME_SPIKE", "deviation": 4.2},
    ))
    await asyncio.sleep(0.05)

    check(
        "Basic pub/sub — alert delivered to subscriber",
        len(got_alerts) == 1
        and got_alerts[0].content["anomaly_type"] == "VOLUME_SPIKE",
        f"received={len(got_alerts)}  "
        f"content={got_alerts[0].content if got_alerts else 'none'}",
    )

    # ── 2. Lamport clocks strictly increasing ─────────────────────────
    lamports: list[int] = []

    async def on_report(m: Message):
        lamports.append(m.lamport_ts)

    bus.subscribe(Topic.THREAT_REPORTS, on_report)

    for _ in range(6):
        await bus.publish(_msg(
            Performative.INFORM, "ACA:1", Topic.THREAT_REPORTS,
            {"severity": 0.85},
        ))
    await asyncio.sleep(0.1)

    monotonic = all(lamports[i] < lamports[i + 1] for i in range(len(lamports) - 1))
    check(
        "Lamport clocks are strictly increasing",
        monotonic and len(lamports) == 6,
        f"values={lamports}",
    )

    # ── 3. Deduplication — same (sender, seq) dropped ─────────────────
    dedup_got: list[Message] = []

    async def on_intel(m: Message):
        dedup_got.append(m)

    bus.subscribe(Topic.THREAT_INTEL, on_intel)

    dup = _msg(Performative.INFORM, "TIA:1", Topic.THREAT_INTEL,
               {"threat_id": "t-001"}, seq=99)
    await bus.publish(dup)
    await bus.publish(dup)   # duplicate
    await bus.publish(dup)   # duplicate
    await asyncio.sleep(0.1)

    check(
        "Duplicate messages (same sender+seq) are silently dropped",
        len(dedup_got) == 1 and bus.dropped_count == 2,
        f"delivered={len(dedup_got)}  dropped={bus.dropped_count}",
    )

    # ── 4. FIFO ordering within a topic ───────────────────────────────
    fifo_order: list[int] = []

    async def on_bid(m: Message):
        fifo_order.append(m.content["n"])

    bus.subscribe(Topic.RESOURCE_BIDS, on_bid)

    for n in range(6):
        await bus.publish(_msg(
            Performative.BID, "RCA:2", Topic.RESOURCE_BIDS,
            {"n": n, "bid_value": 0.7},
        ))
    await asyncio.sleep(0.1)

    check(
        "Messages arrive in FIFO order within a topic",
        fifo_order == list(range(6)),
        f"order received={fifo_order}",
    )

    # ── 5. Topic isolation — no cross-topic delivery ──────────────────
    stray: list[Message] = []

    async def on_resolution(m: Message):
        stray.append(m)

    bus.subscribe(Topic.RESOLUTION, on_resolution)

    # Publish ONLY to COALITION — resolution subscriber should get nothing
    await bus.publish(_msg(
        Performative.REQUEST, "TIA:1", Topic.COALITION,
        {"threat_id": "t-002"},
    ))
    await asyncio.sleep(0.05)

    check(
        "Topic isolation — coalition message does not reach resolution subscriber",
        len(stray) == 0,
        f"stray messages received={len(stray)}",
    )

    # ── 6. Multiple subscribers on the same topic ─────────────────────
    sub_a: list[str] = []
    sub_b: list[str] = []

    async def handler_a(m: Message):
        sub_a.append(m.content["id"])

    async def handler_b(m: Message):
        sub_b.append(m.content["id"])

    bus.subscribe(Topic.VOTES, handler_a)
    bus.subscribe(Topic.VOTES, handler_b)

    for i in range(3):
        await bus.publish(_msg(
            Performative.PROPOSE, "RCA:1", Topic.VOTES,
            {"id": f"vote-{i}", "proposal": "QUARANTINE"},
        ))
    await asyncio.sleep(0.1)

    check(
        "Two subscribers on the same topic both receive all messages",
        sub_a == ["vote-0", "vote-1", "vote-2"]
        and sub_b == ["vote-0", "vote-1", "vote-2"],
        f"subscriber_a={sub_a}  subscriber_b={sub_b}",
    )

    # ── 7. All FIPA-ACL performatives accepted ─────────────────────────
    perfs_seen: list[str] = []

    async def on_grants(m: Message):
        perfs_seen.append(m.performative.value)

    bus.subscribe(Topic.RESOURCE_GRANTS, on_grants)

    for perf in [
        Performative.INFORM,
        Performative.FAILURE,
        Performative.NOT_UNDERSTOOD,
        Performative.ACCEPT,
        Performative.REJECT,
    ]:
        await bus.publish(_msg(perf, "RAA:1", Topic.RESOURCE_GRANTS,
                               {"detail": perf.value}))
    await asyncio.sleep(0.1)

    check(
        "All FIPA-ACL performatives are accepted and delivered",
        len(perfs_seen) == 5,
        f"received={perfs_seen}",
    )

    # ── 8. Bus stats are consistent ───────────────────────────────────
    await bus.stop()
    s = bus.stats()
    stats_ok = (
        s["published"] > 0
        and s["delivered"] >= s["published"]   # each publish → ≥1 delivery
        and s["dropped"]  == 2                 # only the two duplicates
        and s["lamport_now"] >= s["published"]
    )
    check(
        "Bus stats are consistent (published / delivered / dropped / lamport)",
        stats_ok,
        f"published={s['published']}  delivered={s['delivered']}  "
        f"dropped={s['dropped']}  lamport={s['lamport_now']}",
    )

    # ── summary ───────────────────────────────────────────────────────
    print()
    print(f"  Overall: {'ALL PASS' if all_ok else 'SOME FAILURES'}")
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(main())
