#!/usr/bin/env python
"""Write one KERI interop vector file per key event log, into keri-<version>/."""

import argparse
import json
import random
from pathlib import Path

import keri

# `keri.core.eventing` must be imported before `keri.db.basing` — importing basing first hits a
# circular import between the two.
from keri.core import eventing, parsing
from keri.core.coring import Diger, MtrDex
from keri.core.eventing import incept, interact, messagize, rotate
from keri.core.signing import Signer
from keri.db import basing

random.seed(0)


def make_signer(transferable=True):
    return Signer(raw=random.randbytes(32), code=MtrDex.Ed25519_Seed, transferable=transferable)


def commitment(signer):
    # Digest of the qb64 public key, not its raw bytes.
    return Diger(ser=signer.verfer.qb64b, code=MtrDex.Blake3_256).qb64


def key(signer):
    # The same seed derives a transferable D… and a non-transferable B… key, so the log has to say
    # which one it means.
    return {"seed": signer.raw.hex(), "public": signer.verfer.qb64}


def key_state(stream):
    with basing.openDB(name="generate-event-vectors", temp=True) as db:
        kevery = eventing.Kevery(db=db)
        parsing.Parser(kvy=kevery).parse(ims=bytearray(stream.encode("utf-8")))
        state = kevery.kevers[next(iter(kevery.kevers))].state()._asdict()

    # First-seen wall clock — would differ on every run.
    del state["dt"]
    return state


class Log:
    """
    One identifier, and only what is on the wire. An event carries no constructor arguments and
    no signer list: both are recoverable from `sad` and the signature indices in `attachments`,
    which is what keeps the vectors usable from any implementation.
    """

    def __init__(self, name, controllers, backers=(), version="1.0"):
        self.name = name
        self.version = version
        self.controllers = controllers
        self.backers = backers
        self.events = []

    def append(self, name, serder, signers, indices=None, witnesses=()):
        indices = list(range(len(signers))) if indices is None else indices
        sigers = [signers[index].sign(serder.raw, index) for index in indices]
        wigers = [witness.sign(serder.raw, index) for index, witness in enumerate(witnesses)]

        stream = messagize(serder=serder, sigers=sigers, wigers=wigers, pipelined=True).decode("utf-8")

        self.events.append(
            {
                "name": name,
                "sad": serder.ked,
                "raw": serder.raw.decode("utf-8"),
                "attachments": stream[len(serder.raw) :],
            }
        )

    def dump(self):
        return {
            "keripy": keri.__version__,
            "name": self.name,
            "version": self.version,
            "controllers": [key(signer) for signer in self.controllers],
            "backers": [key(signer) for signer in self.backers],
            "events": self.events,
            "state": key_state("".join(event["raw"] + event["attachments"] for event in self.events)),
        }


def single():
    current = make_signer()
    next_ = make_signer()
    after = make_signer()
    log = Log("singlesig", [current, next_, after])

    # Without code= keripy derives a basic prefix from the public key, not a self-addressing one.
    inception = incept(keys=[current.verfer.qb64], ndigs=[commitment(next_)], code=MtrDex.Blake3_256)
    log.append("icp", inception, [current])

    interaction = interact(pre=inception.pre, dig=inception.said, sn=1)
    log.append("ixn-no-data", interaction, [current])

    interaction = interact(pre=inception.pre, dig=interaction.said, sn=2, data=[{"msg": "foobar"}])
    log.append("ixn-data", interaction, [current])

    rotation = rotate(
        pre=inception.pre,
        keys=[next_.verfer.qb64],
        dig=interaction.said,
        sn=3,
        ndigs=[commitment(after)],
    )
    log.append("rot", rotation, [next_])

    interaction = interact(pre=inception.pre, dig=rotation.said, sn=4)
    log.append("ixn-after-rot", interaction, [next_])

    return log


def multisig(name, threshold):
    current = [make_signer() for _ in range(3)]
    next_ = [make_signer() for _ in range(3)]
    after = [make_signer() for _ in range(3)]
    log = Log(name, current + next_ + after)

    inception = incept(
        keys=[signer.verfer.qb64 for signer in current],
        isith=threshold,
        ndigs=[commitment(signer) for signer in next_],
        nsith=threshold,
        code=MtrDex.Blake3_256,
    )
    log.append("icp", inception, current, indices=[0, 2])

    interaction = interact(pre=inception.pre, dig=inception.said, sn=1)
    log.append("ixn", interaction, current, indices=[0, 1])

    rotation = rotate(
        pre=inception.pre,
        keys=[signer.verfer.qb64 for signer in next_],
        dig=interaction.said,
        sn=2,
        isith=threshold,
        ndigs=[commitment(signer) for signer in after],
        nsith=threshold,
    )
    log.append("rot", rotation, next_, indices=[0, 2])

    return log


def backers():
    signers = [make_signer() for _ in range(4)]
    witnesses = [make_signer(transferable=False) for _ in range(4)]
    keys = [witness.verfer.qb64 for witness in witnesses]
    log = Log("backers", signers, witnesses)

    inception = incept(
        keys=[signers[0].verfer.qb64],
        ndigs=[commitment(signers[1])],
        wits=keys[:3],
        code=MtrDex.Blake3_256,
    )
    log.append("icp", inception, [signers[0]], witnesses=witnesses[:3])

    cut = rotate(
        pre=inception.pre,
        keys=[signers[1].verfer.qb64],
        dig=inception.said,
        sn=1,
        ndigs=[commitment(signers[2])],
        wits=keys[:3],
        cuts=[keys[0]],
    )
    log.append("rot-cut-backer", cut, [signers[1]], witnesses=witnesses[1:3])

    add = rotate(
        pre=inception.pre,
        keys=[signers[2].verfer.qb64],
        dig=cut.said,
        sn=2,
        ndigs=[commitment(signers[3])],
        wits=keys[1:3],
        adds=[keys[3]],
    )
    log.append("rot-add-backer", add, [signers[2]], witnesses=witnesses[1:4])

    return log


def hex_threshold():
    current = [make_signer() for _ in range(10)]
    next_ = [make_signer() for _ in range(10)]
    log = Log("hex-threshold", current + next_)

    # Ten of ten, which KERI writes as "a" — the smallest threshold where hex and decimal differ.
    inception = incept(
        keys=[signer.verfer.qb64 for signer in current],
        isith=10,
        ndigs=[commitment(signer) for signer in next_],
        nsith=10,
        code=MtrDex.Blake3_256,
    )
    log.append("icp", inception, current)

    return log


logs = [
    single(),
    multisig("multisig", "2"),
    multisig("multisig-weighted", ["1/2", "1/2", "1/2"]),
    backers(),
    hex_threshold(),
]

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", type=Path, help="where the keri-<version> directory is written")
target = parser.parse_args().directory / f"keri-{keri.__version__}"

# The directory is owned by this script, so a renamed log leaves no stale file behind for the
# tests to pick up.
if target.exists():
    for stale in target.glob("*.json"):
        stale.unlink()
target.mkdir(parents=True, exist_ok=True)

for log in logs:
    path = target / f"{log.name}.json"
    path.write_text(json.dumps(log.dump(), indent=2) + "\n")
    print(path)
