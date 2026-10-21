import asyncio
import os

import pytest
import zstandard

from p2pact import learn
from p2pact.common import COMMON_DICT
from p2pact.compress import Dict, DictStore, compress, decompress
from p2pact.learn import History, history_path
from p2pact.node import P2PACTError

from test_node import echo, make, pair


def chat_line(i: int) -> bytes:
    words = ["the agent", "finished", "the task", "run the tests", "and commit", "messages do not reach",
             "the phone", "why is it so slow", "checked the logs", "a delivery bug", "fixed it", "pushed to the branch"]
    return (f"step {i}: " + "".join(words[(i * 7 + j * j) % len(words)] + ", " for j in range(12))).encode()


def test_dict(seed: int) -> bytes:
    phrases = ["let's do it", "do the messages go through the server or not?", "why is it so slow",
               "run the tests and commit", "the agent finished the task", "messages do not reach the phone",
               "Done. Tests pass, changes are in the repository.", "Checked the logs: a delivery bug, fixed."]
    n = len(phrases)
    samples = [f"{phrases[(i + seed) % n]} {i} — {phrases[(i * 3) % n]}, {phrases[(i * 5 + seed) % n]}".encode()
               for i in range(400)]
    return zstandard.train_dictionary(8 << 10, samples, dict_id=40000 + seed).as_bytes()


test_dict.__test__ = False

LONG = b"do the messages go through the server or not? run the tests and commit, the agent finished the task"


@pytest.fixture
def quick(monkeypatch):
    """Learning on a short clock."""
    monkeypatch.setattr(learn, "LEARN_TICK", 0.1)
    monkeypatch.setattr(learn, "LEARN_LULL", 0.3)


async def wait_for(what, cond, timeout=10.0):
    for _ in range(int(timeout / 0.02)):
        if cond():
            return
        await asyncio.sleep(0.02)
    raise AssertionError(what)


def test_round_trip():
    d = Dict(test_dict(0))
    for dd, slot in ((d, 3), (None, 0)):
        z = compress(LONG, dd, slot)
        assert z and z[0] == slot
        assert decompress(z, dd, 1 << 20) == LONG
    assert len(compress(LONG, d, 1)) < len(compress(LONG, None, 0))
    assert compress(b"short", d, 1) is None
    long = LONG * 20  # past 1 KB: the slower level
    assert decompress(compress(long, d, 1), d, 1 << 20) == long
    with pytest.raises(Exception):
        decompress(compress(LONG, d, 1), None, 1 << 20)


def test_common_dict():
    d = Dict(COMMON_DICT)
    assert len(COMMON_DICT) == 64 << 10 and d.zid == 1345470787
    msg = "The agent finished the task: tests pass, the changes are in the repository.".encode()
    assert len(compress(msg, d, 1)) < len(compress(msg, None, 0) or msg)


def test_pick(tmp_path):
    s = DictStore(str(tmp_path))
    old, fresh = Dict(test_dict(0)), Dict(test_dict(1))
    s.add(old)
    s.add(fresh)
    d, slot = s.pick("x", [old.id, fresh.id], [])
    assert d is fresh and slot == 2  # slots go by age
    d, slot = s.pick("x", [old.id], [])
    assert d is old and slot == 1
    assert s.pick("x", [], []) == (None, 0)
    assert s.pick("x", [old.id, fresh.id], [fresh.id])[0] is old  # do not use one the other side lost
    again = DictStore(str(tmp_path))
    assert [d.id for d in again.dicts] == [fresh.id, old.id]


def test_own_preferred(tmp_path):
    s = DictStore(str(tmp_path))
    own, common = Dict(test_dict(0), "b", True), Dict(test_dict(1))
    s.add(own)
    s.add(common)  # newer, but ours for b goes first when b has it
    assert s.pick("b", [own.id, common.id], [])[0] is own
    assert s.pick("b", [common.id], [])[0] is common


def test_slots_stay(tmp_path):
    s = DictStore(str(tmp_path))
    ds = [Dict(test_dict(i), "b", True) for i in range(6)]
    s.add(ds[0])
    s.add(ds[1])
    first = s.ids("b")
    s.add(ds[2])
    assert s.ids("b") == first + [ds[2].id]  # a new one does not move the others
    for d in ds[3:]:  # 6 own ones: the 2 oldest are dropped (4 kept)
        s.add(d)
    got = s.ids("b")
    assert len(got) == 6 and got[0] == b"" and got[1] == b"" and got[5] == ds[5].id
    assert s.pick("b", [ds[5].id], [])[1] == 6
    assert s.ids("c") == []


def test_slots_reused_past_max(tmp_path):
    s = DictStore(str(tmp_path))
    ds = [Dict(test_dict(i), "b", True) for i in range(40)]
    for d in ds[:32]:  # listed after each: every one takes a slot of its own
        s.add(d)
        s.ids("b")
    assert len(s.ids("b")) == 32 and s.ids("b")[:28] == [b""] * 28
    s.add(ds[32])  # past 32 slots: the oldest empty one
    got = s.ids("b")
    assert len(got) == 32 and got[0] == ds[32].id


def test_pair_scope(tmp_path):
    s = DictStore(str(tmp_path))
    mine, theirs, common = Dict(test_dict(0), "b", True), Dict(test_dict(1), "b"), Dict(test_dict(2))
    for d in (mine, theirs, common):
        s.add(d)
    assert set(s.ids("b")) == {mine.id, theirs.id, common.id}
    assert s.ids("c") == [common.id]
    assert s.get(mine.id, "c") is None and s.get(theirs.id, "c") is None and s.get(common.id, "c") is common
    again = DictStore(str(tmp_path))
    assert again.ids("c") == [common.id] and again.own("b").id == mine.id
    again.forget("b")
    assert again.ids("b") == [common.id]
    assert sorted(os.listdir(again.dir)) == sorted(["order", common.id.hex()])


def test_order_damaged(tmp_path):
    s = DictStore(str(tmp_path))
    d = Dict(test_dict(0), "b", True)
    s.add(d)
    with open(os.path.join(s.dir, "order"), "w") as f:
        f.write(d.id.hex() + " b\n")
    assert DictStore(str(tmp_path)).ids("c") == []


def test_history_file(tmp_path):
    path = history_path(str(tmp_path), "someone")
    h = History(path)
    for i in range(10):
        m = chat_line(i)
        h.add(m, i % 2 == 1)
        h.save(m, i % 2 == 1)
    h.add(b"x" * 10000, False)  # cut to 4 KB
    h.save(b"x" * 4096, False)
    h.flush()
    with open(path, "ab") as f:
        f.write(b"\x00\x00\xff")  # a torn record
    again = History.load(path)
    assert again.own_size == h.own_size and again.heard_size == h.heard_size and list(again.own) == list(h.own)


def test_train():
    own = [chat_line(i) for i in range(400)]
    d = learn.train(own, [], 8 << 10)
    with_, without = 0, 0
    for i in range(400, 450):
        m = chat_line(i)
        z = compress(m, d, 1)
        assert decompress(z, d, 1 << 20) == m
        with_ += len(z)
        without += len(compress(m, None, 0))
    assert with_ * 2 < without, (with_, without)
    with pytest.raises(Exception):
        learn.train([chat_line(1)], [], 4096)


def test_compressed_call(tmp_path):
    async def run():
        a, b = await make(tmp_path, "laptop"), await make(tmp_path, "phone")
        try:
            await pair(a, b)
            raw = test_dict(0)
            a.add_dict(raw)
            b.add_dict(raw)
            await wait_for("lists", lambda: a.peers[b.id.addr].dicts and b.peers[a.id.addr].dicts)
            await echo(a, b, LONG)
            await echo(b, a, LONG * 50)
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_missing_dict_fetched(tmp_path):
    async def run():
        a, b = await make(tmp_path, "laptop"), await make(tmp_path, "phone")
        try:
            await pair(a, b)
            raw = test_dict(0)
            a.add_dict(raw)
            b.add_dict(raw)
            await wait_for("lists", lambda: a.peers[b.id.addr].dicts and b.peers[a.id.addr].dicts)
            b.dicts.dicts = []  # b lost the dictionary and a does not know
            b.dicts.gen += 1
            for _ in range(3):
                await echo(a, b, LONG)
            assert Dict(raw).id in b.dicts_for(a.id.addr)
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_fetch_new(tmp_path):
    """A dictionary in the other's list that we lack is fetched; it belongs to the pair."""
    async def run():
        a, b, c = await make(tmp_path, "laptop"), await make(tmp_path, "phone"), await make(tmp_path, "mac")
        try:
            await pair(a, b)
            await pair(a, c)
            raw = test_dict(0)
            a.add_dict(raw)
            id_ = Dict(raw).id
            await wait_for("b did not fetch a's dictionary", lambda: b.dicts.get(id_, a.id.addr) is not None)
            await wait_for("c did not fetch a's dictionary", lambda: c.dicts.get(id_, a.id.addr) is not None)
            assert b.dicts.get(id_, a.id.addr).peer == a.id.addr  # not common for b
            await wait_for("a does not use it", lambda: a.dict_state(b.id.addr)[1] == id_)
            await echo(a, b, LONG)
        finally:
            for n in (a, b, c):
                n.close()
    asyncio.run(run())


def test_own_dictionary(tmp_path, quick):
    """A device trains its own dictionary for the device it talks to; that device fetches it, and
    then messages go compressed with it. A third device neither sees nor gets it, from either."""
    async def run():
        a, b, c = await make(tmp_path, "laptop"), await make(tmp_path, "phone"), await make(tmp_path, "mac")
        try:
            await pair(a, b)
            await pair(a, c)
            await pair(b, c)
            for i in range(300):
                await echo(a, b, chat_line(i))
            await wait_for("a did not train for b", lambda: a.dicts.own(b.id.addr) is not None)
            own = a.dicts.own(b.id.addr)
            await wait_for("b did not take a's dictionary", lambda: a.dict_state(b.id.addr)[1] == own.id)
            await echo(a, b, chat_line(1000))
            assert len(compress(chat_line(1000), own, 1)) < len(compress(chat_line(1000), None, 0))
            assert own.id not in c.dicts_for(a.id.addr) and own.id not in a.dicts_for(c.id.addr)
            for frm in (a, b):
                with pytest.raises(P2PACTError):
                    await asyncio.wait_for(c.call(frm.id.addr, 0, 5, own.id), 5)
            # it survives a restart: the history and the dictionary are on disk
            h = a.peers[b.id.addr].hist
            again = DictStore(a.dir)
            assert again.own(b.id.addr).id == own.id
            loaded = History.load(history_path(a.dir, b.id.addr))
            assert loaded.own_size == h.own_size and loaded.heard_size > 0
            a.forget(b.id.addr)
            assert a.dicts.own(b.id.addr) is None and not os.path.exists(history_path(a.dir, b.id.addr))
        finally:
            for n in (a, b, c):
                n.close()
    asyncio.run(run())


def test_train_in_lull(tmp_path, quick, monkeypatch):
    monkeypatch.setattr(learn, "LEARN_LULL", 1.0)
    monkeypatch.setattr(learn, "LEARN_WAIT", 3600.0)

    async def run():
        a, b = await make(tmp_path, "laptop"), await make(tmp_path, "phone")
        try:
            await pair(a, b)
            loop = asyncio.get_running_loop()
            until = loop.time() + 3
            i = 0
            while loop.time() < until:  # 32 KB first, then on and on
                await echo(a, b, chat_line(i))
                if i > 250:
                    await asyncio.sleep(0.2)
                i += 1
            assert a.dicts.own(b.id.addr) is None, "trained in the middle of the conversation"
            await wait_for("did not train in the lull", lambda: a.dicts.own(b.id.addr) is not None)
        finally:
            a.close()
            b.close()
    asyncio.run(run())


def test_no_dict_for_listener(tmp_path, quick):
    """A device that only receives trains nothing: the dictionary is for what it sends."""
    async def run():
        a, b = await make(tmp_path, "laptop"), await make(tmp_path, "phone")
        try:
            await pair(a, b)
            b.handle(64, 2, lambda peer, args: [])
            for i in range(300):
                await asyncio.wait_for(a.call(b.id.addr, 64, 2, chat_line(i)), 10)
            await wait_for("a did not train", lambda: a.dicts.own(b.id.addr) is not None)
            await asyncio.sleep(1)
            assert b.dicts.own(a.id.addr) is None
        finally:
            a.close()
            b.close()
    asyncio.run(run())
