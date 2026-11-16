"""Ephemeral test vectors only; never used by the application."""
import base64
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[3]))
from cryptography.hazmat.primitives import serialization
from crypto_engine import signatures as rsa, dh_exchange as dh, aes_gcm as aes
from crypto_engine.hash_chain import canonical_json, canonical_record, record_hash, genesis_hash
from tools.verify_transcript import verify_evidence
b64=lambda b:base64.b64encode(b).decode()
u=base64.b64decode
if sys.argv[1]=='generate':
    private,public=rsa.generate_keypair()
    a,ap=dh.generate_keypair();b,bp=dh.generate_keypair()
    record=dict(sender='alice',recipient='bob',seq=1,timestamp=1800000000,
        message='Unicode: नमस्ते 🙂 / \x7f \n " \\',prev_hash=genesis_hash(ap,bp,'alice'))
    key=dh.compute_shared_key(a,bp)
    payload={k:record[k] for k in ('message','seq','timestamp','prev_hash')}
    payload['signature']=b64(rsa.sign(private,canonical_record(**record)))
    box=aes.encrypt(key,canonical_json(payload))
    print(json.dumps(dict(public_pem=rsa.serialize_public_key(public).decode(),
        handshake_pub=b64(ap),handshake_sig=b64(rsa.sign(private,ap)),
        peer_pub=b64(bp),peer_private=b64(b.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())),
        record=record,canonical=canonical_json(record).decode(),record_hash=record_hash(canonical_record(**record)),
        box={k:b64(v) for k,v in box.items()},fingerprint=rsa.fingerprint(rsa.serialize_public_key(public)))))
elif sys.argv[1]=='verify':
    d=json.load(sys.stdin);pub=rsa.deserialize_public_key(d['public_pem'].encode())
    assert rsa.verify(pub,u(d['handshake_pub']),u(d['handshake_sig']))
    assert rsa.verify(pub,canonical_record(**d['record']),u(d['signature']))
    assert record_hash(canonical_record(**d['record']))==d['record_hash']
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    key=dh.compute_shared_key(X25519PrivateKey.from_private_bytes(u(d['peer_private'])),u(d['handshake_pub']))
    plaintext=aes.decrypt(key,**{k:u(v) for k,v in d['box'].items()})
    assert json.loads(plaintext)['message']==d['record']['message']
    print('VERIFIED')
