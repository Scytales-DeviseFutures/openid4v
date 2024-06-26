#!/usr/bin/env python3
import json

from idpyoidc.util import load_config_file

from fedservice.combo import FederationCombo
from fedservice.utils import make_federation_combo
from utils import load_values_from_file

ENTITY = json.loads(open("entities.json", 'r').read())


def get_federation_entity(entity):
    if isinstance(entity, FederationCombo):
        return entity["federation_entity"]
    else:
        return entity


fed_entity = {}
combo_entity = {}

for ent, info in ENTITY.items():
    _cnf = load_values_from_file(load_config_file(f"{info['dir']}/{info['config']}"))
    _ent = make_federation_combo(**_cnf["entity"])
    if isinstance(_ent, FederationCombo):
        fed_entity[ent] = _ent["federation_entity"]
        combo_entity[ent] = _ent
    else:
        fed_entity[ent] = _ent

subordinates = {}
trust_anchor = {}

for ent, info in ENTITY.items():
    print(f"*** {ent} ***")
    if "authority_hints" in info and info["authority_hints"]:
        authorities = []
        for auth in info["authority_hints"]:
            authorities.append(fed_entity[auth].entity_id)
            if auth not in subordinates:
                subordinates[auth] = {}
            _ent_id = get_federation_entity(fed_entity[ent]).entity_id
            _sub_info = {
                'jwks': get_federation_entity(fed_entity[ent]).keyjar.export_jwks(),
                'authority_hints': [fed_entity[auth].entity_id],
            }
            if fed_entity[ent].server.subordinate != {}:
                _sub_info["intermediate"] = True
            if ent in combo_entity:
                _sub_info["entity_type"] = list(combo_entity[ent]._part.keys())
            else:
                _sub_info["entity_type"] = ["federation_entity"]

            subordinates[auth][_ent_id] = _sub_info
        print(f"authority_hints: {authorities}")
        file_name = f"{info['dir']}/{ent}_authority_hints.json"
        with open(file_name, "w") as fp:
            fp.write(json.dumps(authorities))
    if "trust_anchors" in info and info["trust_anchors"]:
        trust_anchor[ent] = {}
        for anch in info["trust_anchors"]:
            _fed_entity = get_federation_entity(fed_entity[anch])
            _ent_id = _fed_entity.entity_id
            trust_anchor[ent][_ent_id] = _fed_entity.keyjar.export_jwks()
    if "trust_marks" in info and info["trust_marks"]:
        trust_marks = []
        for issuer_id, tm_id in info["trust_marks"].items():
            _fed_entity = get_federation_entity(fed_entity[issuer_id])
            _tm_issuer = _fed_entity.get_endpoint("status").trust_mark_issuer
            entity_id = get_federation_entity(fed_entity[ent]).entity_id
            trust_marks.append(_tm_issuer.create_trust_mark(tm_id, entity_id))
        file_name = f"{info['dir']}/{ent}_trust_marks.json"
        with open(file_name, "w") as fp:
            fp.write(json.dumps(trust_marks))


trust_anchors = {}
for ent, info in trust_anchor.items():
    for k,v in info.items():
        trust_anchors[k] = v

print(f"Trust Anchors: {trust_anchors}")
with open("trust_anchors.json", "w") as fp:
    fp.write(json.dumps(trust_anchors))

for auth, val in subordinates.items():
    file_name = f"{ENTITY[auth]['dir']}/{auth}_subordinates.json"
    with open(file_name, "w") as fp:
        fp.write(json.dumps(val))

    print(f"*** subordinates@{auth} ***")
    for sub, info in val.items():
        print(f"--- {sub} ---")
        print(info)

for ent, val in trust_anchor.items():
    file_name = f"{ENTITY[ent]['dir']}/{ent}_trust_anchors.json"
    with open(file_name, "w") as fp:
        fp.write(json.dumps(val))

    print(f"*** trust_anchors@{ent} ***")
    for sub, info in val.items():
        print(f"--- {sub} ---")
        print(info)
