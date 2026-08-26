#!/usr/bin/env python
import json
import random

import keri

# `keri.core.eventing` must be imported before `keri.db.basing` — importing basing first hits a
# circular import between the two.
from keri.core import eventing, parsing
from keri.core.coring import Diger, MtrDex
from keri.core.eventing import incept, interact, messagize, rotate
from keri.core.signing import Signer
from keri.db import basing

random.seed(0)

events = []


def make_signer():
    return Signer(raw=random.randbytes(32), code=MtrDex.Ed25519_Seed, transferable=True)


def commitment(signer):
    # Digest of the qb64 public key, not its raw bytes.
    return Diger(ser=signer.verfer.qb64b, code=MtrDex.Blake3_256).qb64


def append(name, serder, signers, args):
    sigers = [signer.sign(serder.raw, index) for index, signer in enumerate(signers)]

    events.append(
        {
            "name": name,
            "version": "1.0",
            "seeds": [signer.raw.hex() for signer in signers],
            "args": args,
            "sad": serder.ked,
            "raw": serder.raw.decode("utf-8"),
            "stream": messagize(serder=serder, sigers=sigers, pipelined=True).decode("utf-8"),
        }
    )


def key_state(kel):
    with basing.openDB(name="generate-event-vectors", temp=True) as db:
        kevery = eventing.Kevery(db=db)
        parsing.Parser(kvy=kevery).parse(ims=bytearray(kel.encode("utf-8")))
        state = kevery.kevers[next(iter(kevery.kevers))].state()._asdict()

    # First-seen wall clock — would differ on every run.
    del state["dt"]
    return state


current = make_signer()
next_ = make_signer()
after = make_signer()

next_digest = commitment(next_)
# Without code= keripy derives a basic prefix from the public key, not a self-addressing one.
inception = incept(keys=[current.verfer.qb64], ndigs=[next_digest], code=MtrDex.Blake3_256)
append(
    "icp-1of1",
    inception,
    [current],
    {"signingKeys": [current.verfer.qb64], "nextKeyDigests": [next_digest]},
)

interaction = interact(pre=inception.pre, dig=inception.said, sn=1)
append("ixn-no-data", interaction, [current], {})

data = {"msg": "foobar"}
interaction = interact(pre=inception.pre, dig=interaction.said, sn=2, data=[data])
append("ixn-data", interaction, [current], {"data": data})

after_digest = commitment(after)
rotation = rotate(
    pre=inception.pre,
    keys=[next_.verfer.qb64],
    dig=interaction.said,
    sn=3,
    ndigs=[after_digest],
)
append(
    "rot-1of1",
    rotation,
    [next_],
    {"signingKeys": [next_.verfer.qb64], "nextKeyDigests": [after_digest]},
)

interaction = interact(pre=inception.pre, dig=rotation.said, sn=4)
append("ixn-after-rot", interaction, [next_], {})

kel = "".join(event["stream"] for event in events)

print(
    json.dumps(
        {
            "keripy": keri.__version__,
            "events": events,
            "kel": {"stream": kel, "state": key_state(kel)},
        },
        indent=2,
    )
)
