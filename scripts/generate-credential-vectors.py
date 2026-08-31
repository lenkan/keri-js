#!/usr/bin/env python
"""Write ACDC interop vectors — a QVI credential and a Legal Entity credential chained to it."""

import argparse
import json
import random
from pathlib import Path

import keri

# `keri.core.eventing` must be imported before `keri.db.basing` — importing basing first hits a
# circular import between the two.
from keri.core import eventing, parsing
from keri.core.coring import Diger, MtrDex, Saider, Saids, Seqner
from keri.core.counting import Codens, Counter
from keri.core.eventing import incept, interact, messagize
from keri.core.signing import Signer
from keri.db import basing
from keri.kering import Vrsn_1_0
from keri.vc.proving import credential
from keri.vdr import eventing as tel
from keri.vdr import viring
from keri.vdr.eventing import TraitDex

random.seed(0)

# The real vLEI schema SAIDs, from keripy's own demo scripts. Nothing resolves them: offline
# verification reports `schema` as unchecked, so they travel as opaque strings.
QVI_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
LE_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"

# Every timestamp is fixed. keripy would otherwise stamp `now`, and the fixture would churn on
# every regeneration.
DT = "2025-04-17T21:53:17.019676+00:00"

RULES = {
    "d": "",
    "usageDisclaimer": {
        "l": (
            "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the "
            "associated Ecosystem Governance Framework, does not assert that the Legal Entity is "
            "trustworthy, honest, reputable in its business dealings, safe to do business with, or "
            "compliant with any laws."
        )
    },
}


def make_signer(transferable=True):
    return Signer(raw=random.randbytes(32), code=MtrDex.Ed25519_Seed, transferable=transferable)


def commitment(signer):
    # Digest of the qb64 public key, not its raw bytes.
    return Diger(ser=signer.verfer.qb64b, code=MtrDex.Blake3_256).qb64


def key(signer):
    return {"seed": signer.raw.hex(), "public": signer.verfer.qb64}


def saidify(sad):
    _, out = Saider.saidify(sad=sad, label=Saids.d)
    return out


def settle(stream, identifiers, credentials):
    """
    Replay the KEL and TEL through keripy's own Kevery and Tevery, and return the key states.

    A fixture keripy will not settle is not a fixture: a `vcp` missing `NB` still parses, and its
    `iss` events still look well formed, but the registry rejects every one of them.
    """
    with basing.openDB(name="generate-credential-vectors", temp=True) as db:
        reger = viring.Reger(name="generate-credential-vectors", temp=True, db=db)
        kevery = eventing.Kevery(db=db, lax=True, local=False)
        tevery = tel.Tevery(reger=reger, db=db, lax=True, local=False)
        parsing.Parser(kvy=kevery, tvy=tevery).parse(ims=bytearray(stream.encode("utf-8")))

        states = {}
        for prefix in identifiers:
            if prefix not in kevery.kevers:
                raise SystemExit(f"keripy did not settle {prefix}: it settled {sorted(kevery.kevers)}")
            state = kevery.kevers[prefix].state()._asdict()
            # First-seen wall clock — would differ on every run.
            del state["dt"]
            states[prefix] = state

        for said, registry in credentials:
            if registry not in tevery.tevers:
                raise SystemExit(f"keripy did not settle registry {registry}")
            status = tevery.tevers[registry].vcState(said)
            if status is None or status.et != "iss":
                raise SystemExit(f"keripy did not issue {said}: {status and status.et}")

    return states


def tel_seal(serder):
    """The KEL seal that anchors a TEL event. `i` is the TEL's own identifier, not the issuer's."""
    return {"i": serder.pre, "s": serder.ked["s"], "d": serder.said}


def source_couple(anchor):
    """Names the KEL event carrying the seal, which is how a TEL event travels."""
    counter = Counter(Codens.SealSourceCouples, count=1, gvrsn=Vrsn_1_0)
    return counter.qb64 + Seqner(snh=anchor.ked["s"]).qb64 + anchor.said


def source_triple(creder, issuance):
    """`keri.app.signing.serialize` — what `kli vc export` attaches to an ACDC."""
    counter = Counter(Codens.SealSourceTriples, count=1, gvrsn=Vrsn_1_0)
    return counter.qb64 + creder.said + Seqner(snh=issuance.ked["s"]).qb64 + issuance.said


class Issuer:
    """One AID with its own KEL and one credential registry, tracked so events chain in order."""

    def __init__(self, log, name, current, next_):
        self.log = log
        self.name = name
        self.current = current
        self.next = next_

        self.icp = incept(
            keys=[current.verfer.qb64],
            ndigs=[commitment(next_)],
            code=MtrDex.Blake3_256,
        )
        self.pre = self.icp.pre
        self.latest = self.icp
        self.sn = 0
        log.kel(f"{name}-icp", self.icp, current)

    def anchor(self, name, seal):
        self.sn += 1
        event = interact(pre=self.pre, dig=self.latest.said, sn=self.sn, data=[seal])
        self.latest = event
        self.log.kel(name, event, self.current)
        return event

    def make_registry(self, nonce):
        # Without `NB` keripy builds a backer-based registry, which rejects a plain `iss` in favour
        # of `bis`. v2 drops backered registries; the KEL is what carries the backing.
        self.vcp = tel.incept(pre=self.pre, nonce=nonce, cnfg=[TraitDex.NoBackers])
        self.regk = self.vcp.pre
        anchor = self.anchor(f"{self.name}-ixn-vcp", tel_seal(self.vcp))
        self.log.tel(f"{self.name}-vcp", self.vcp, anchor)
        return self.vcp

    def issue(self, name, creder):
        iss = tel.issue(vcdig=creder.said, regk=self.regk, dt=DT)
        anchor = self.anchor(f"{name}-ixn-iss", tel_seal(iss))
        self.log.tel(f"{name}-iss", iss, anchor)
        return iss


class Log:
    """
    Messages in stream order, and only what is on the wire. KEL events come first so a TEL event's
    anchor is always already seen — the order `kli vc export` emits, and the order keripy needs to
    settle rather than escrow.
    """

    def __init__(self, name, version="1.0"):
        self.name = name
        self.version = version
        self.controllers = []
        self.key_events = []
        self.transaction_events = []
        self.credentials = []
        self.identifiers = []
        self.issued = []

    def kel(self, name, serder, signer):
        sigers = [signer.sign(serder.raw, 0)]
        stream = messagize(serder=serder, sigers=sigers, pipelined=True).decode("utf-8")
        self.key_events.append(entry(name, serder, stream[len(serder.raw) :]))

    def tel(self, name, serder, anchor):
        attachments = source_couple(anchor)
        group = Counter(Codens.AttachmentGroup, count=len(attachments) // 4, gvrsn=Vrsn_1_0)
        self.transaction_events.append(entry(name, serder, group.qb64 + attachments))

    def credential(self, name, creder, issuance):
        self.credentials.append(entry(name, creder, source_triple(creder, issuance)))
        self.issued.append((creder.said, creder.regi))

    @property
    def events(self):
        return self.key_events + self.transaction_events + self.credentials

    def dump(self):
        # The ACDCs are left out: a bare Parser has no verifier to hand them to and drops them,
        # while the KEL and TEL are what Kevery and Tevery settle.
        replayed = self.key_events + self.transaction_events
        stream = "".join(event["raw"] + event["attachments"] for event in replayed)

        return {
            "keripy": keri.__version__,
            "name": self.name,
            "version": self.version,
            "controllers": [key(signer) for signer in self.controllers],
            "events": self.events,
            "states": settle(stream, self.identifiers, self.issued),
        }


def entry(name, serder, attachments):
    return {
        "name": name,
        "sad": serder.sad if hasattr(serder, "sad") else serder.ked,
        "raw": serder.raw.decode("utf-8"),
        "attachments": attachments,
    }


def chained():
    """
    The vLEI chain. GLEIF issues a QVI credential to the QVI; the QVI issues a Legal Entity
    credential to the holder, with an edge naming the QVI credential.

    The edge is `I2I`, so it only holds because the Legal Entity credential's issuer is the QVI
    credential's issuee. An edge that merely named a SAID would not exercise that.
    """
    log = Log("chained")

    signers = [make_signer() for _ in range(6)]
    log.controllers = signers

    gleif = Issuer(log, "gleif", signers[0], signers[1])
    qvi = Issuer(log, "qvi", signers[2], signers[3])
    holder = Issuer(log, "holder", signers[4], signers[5])
    log.identifiers = [gleif.pre, qvi.pre, holder.pre]

    gleif.make_registry(nonce="0AAr75cmjijU8_h_MYwJAwuk")
    qvi.make_registry(nonce="0AAr75cmjijU8_h_MYwJAwul")

    qvi_credential = credential(
        schema=QVI_SCHEMA,
        issuer=gleif.pre,
        recipient=qvi.pre,
        data={"dt": DT, "LEI": "254900OPPU84GM83MG36"},
        status=gleif.regk,
        rules=saidify(dict(RULES)),
    )
    qvi_issuance = gleif.issue("qvi-credential", qvi_credential)

    # The edge block is saidified by the caller: `proving.credential` assigns `source` to `e`
    # verbatim, unlike the attribute block it saidifies itself.
    edge = saidify({"d": "", "qvi": {"n": qvi_credential.said, "s": QVI_SCHEMA}})

    le_credential = credential(
        schema=LE_SCHEMA,
        issuer=qvi.pre,
        recipient=holder.pre,
        data={"dt": DT, "LEI": "875500ELOZEL05BVXV37"},
        status=qvi.regk,
        source=edge,
        rules=saidify(dict(RULES)),
    )
    le_issuance = qvi.issue("le-credential", le_credential)

    log.credential("qvi-credential", qvi_credential, qvi_issuance)
    log.credential("le-credential", le_credential, le_issuance)

    return log


logs = [chained()]

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", type=Path, help="where the keri-<version> directory is written")
target = parser.parse_args().directory / f"keri-{keri.__version__}"

# The directory is owned by this script, so a renamed log leaves no stale file behind.
if target.exists():
    for stale in target.glob("*.json"):
        stale.unlink()
    for stale in target.glob("*.cesr"):
        stale.unlink()
target.mkdir(parents=True, exist_ok=True)

for log in logs:
    path = target / f"{log.name}.json"
    path.write_text(json.dumps(log.dump(), indent=2) + "\n")
    print(path)

    stream = target / f"{log.name}.cesr"
    stream.write_text("".join(event["raw"] + event["attachments"] for event in log.events))
    print(stream)
