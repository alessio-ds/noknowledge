import sqlite3

import pytest
from fastapi.testclient import TestClient

from noknowledge.server.app import create_app
from noknowledge.server.config import Settings


def make_client(tmp_path, name="relay", **overrides) -> TestClient:
    settings = Settings(
        data_dir=str(tmp_path / name),
        housekeeping_interval=10**9,
        **overrides,
    )
    app = create_app(settings)
    client = TestClient(app)
    client.__enter__()
    return client


@pytest.fixture
def client(tmp_path):
    with make_client(tmp_path) as c:
        yield c


def new_mailbox(client) -> dict:
    response = client.post("/api/mailbox")
    assert response.status_code == 201, response.text
    return response.json()


def auth(mailbox: dict, capability: str = "read") -> dict:
    header = "X-NK-Read" if capability == "read" else "X-NK-Write"
    token = mailbox["read_token"] if capability == "read" else mailbox["write_token"]
    return {header: token}


# -- health and shape -----------------------------------------------------


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["mailboxes"] == 0


# -- discovery ------------------------------------------------------------


def test_relays_endpoint_advertises_configured_peers(tmp_path):
    client = make_client(
        tmp_path,
        advertise_url="https://me.example",
        known_relays=["https://a.example", "https://b.example"],
    )
    try:
        body = client.get("/api/relays").json()
        assert body["advertise"] == "https://me.example"
        assert body["relays"] == [
            "https://me.example",
            "https://a.example",
            "https://b.example",
        ]
    finally:
        client.__exit__(None, None, None)


def test_relays_endpoint_is_empty_by_default(client):
    body = client.get("/api/relays").json()
    assert body["relays"] == []
    assert body["advertise"] is None


def test_relays_endpoint_reads_relays_json(tmp_path):
    client = make_client(tmp_path)
    try:
        (tmp_path / "relay" / "relays.json").write_text(
            '{"relays": ["https://file.example"]}', encoding="utf-8"
        )
        assert client.get("/api/relays").json()["relays"] == ["https://file.example"]
    finally:
        client.__exit__(None, None, None)


def test_relays_endpoint_survives_a_corrupt_relays_json(tmp_path):
    client = make_client(tmp_path)
    try:
        (tmp_path / "relay" / "relays.json").write_text("{not json", encoding="utf-8")
        assert client.get("/api/relays").json()["relays"] == []
    finally:
        client.__exit__(None, None, None)


def test_schema_has_no_identity_tables(tmp_path):
    client = make_client(tmp_path)
    db_path = tmp_path / "relay" / "relay.db"
    connection = sqlite3.connect(db_path)
    tables = {
        row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    connection.close()
    client.__exit__(None, None, None)
    assert "mailboxes" in tables and "messages" in tables
    assert not any("user" in name.lower() for name in tables)
    assert not any("public_key" in name.lower() for name in tables)


# -- mailbox capabilities -------------------------------------------------


def test_create_mailbox_returns_usable_capability(client):
    mailbox = new_mailbox(client)
    assert mailbox["mailbox_id"] and mailbox["read_token"] and mailbox["write_token"]


def test_write_to_nonexistent_mailbox_is_rejected(client):
    """The core anti-spam property: undeliverable mail is never accepted."""
    response = client.post(
        "/api/mailbox/doesnotexist/messages",
        headers={"X-NK-Write": "AAAA"},
        content=b"spam",
    )
    assert response.status_code == 404


def test_write_requires_token(client):
    mailbox = new_mailbox(client)
    response = client.post(
        f"/api/mailbox/{mailbox['mailbox_id']}/messages", content=b"x"
    )
    assert response.status_code == 401


def test_write_rejects_wrong_token(client):
    mailbox = new_mailbox(client)
    other = new_mailbox(client)
    response = client.post(
        f"/api/mailbox/{mailbox['mailbox_id']}/messages",
        headers={"X-NK-Write": other["write_token"]},
        content=b"x",
    )
    assert response.status_code == 401


def test_client_supplied_capability_is_idempotent(client):
    payload = {"mailbox_id": "AbCdEfGh1234", "read_token": "A" * 43, "write_token": "B" * 43}
    # use real 32-byte tokens
    from noknowledge.crypto.encoding import b64e

    payload = {
        "mailbox_id": "AbCdEfGh1234",
        "read_token": b64e(b"r" * 32),
        "write_token": b64e(b"w" * 32),
    }
    first = client.post("/api/mailbox", json=payload)
    second = client.post("/api/mailbox", json=payload)
    assert first.status_code == 201
    assert second.status_code == 201


def test_conflicting_capability_is_rejected(client):
    from noknowledge.crypto.encoding import b64e

    base = {"mailbox_id": "AbCdEfGh1234", "read_token": b64e(b"r" * 32)}
    client.post("/api/mailbox", json={**base, "write_token": b64e(b"w" * 32)})
    response = client.post(
        "/api/mailbox", json={**base, "write_token": b64e(b"z" * 32)}
    )
    assert response.status_code == 409


# -- store and forward ----------------------------------------------------


def test_put_and_fetch_roundtrip(client):
    mailbox = new_mailbox(client)
    response = client.post(
        f"/api/mailbox/{mailbox['mailbox_id']}/messages",
        headers=auth(mailbox, "write"),
        content=b"opaque-ciphertext",
    )
    assert response.status_code == 201
    assert response.json()["seq"] == 1

    fetched = client.get(
        f"/api/mailbox/{mailbox['mailbox_id']}", headers=auth(mailbox, "read")
    )
    assert fetched.status_code == 200
    from noknowledge.crypto.encoding import b64d

    body = fetched.json()
    assert body["next_seq"] == 1
    assert b64d(body["messages"][0]["blob"]) == b"opaque-ciphertext"


def test_fetch_after_seq_skips_acked(client):
    mailbox = new_mailbox(client)
    for index in range(3):
        client.post(
            f"/api/mailbox/{mailbox['mailbox_id']}/messages",
            headers=auth(mailbox, "write"),
            content=f"m{index}".encode(),
        )
    got = client.get(
        f"/api/mailbox/{mailbox['mailbox_id']}",
        headers=auth(mailbox, "read"),
        params={"after_seq": 1},
    ).json()
    assert [m["seq"] for m in got["messages"]] == [2, 3]


def test_ack_deletes_messages(client):
    mailbox = new_mailbox(client)
    for index in range(3):
        client.post(
            f"/api/mailbox/{mailbox['mailbox_id']}/messages",
            headers=auth(mailbox, "write"),
            content=f"m{index}".encode(),
        )
    ack = client.post(
        f"/api/mailbox/{mailbox['mailbox_id']}/ack",
        headers=auth(mailbox, "read"),
        json={"upto_seq": 2},
    )
    assert ack.json()["deleted"] == 2
    remaining = client.get(
        f"/api/mailbox/{mailbox['mailbox_id']}", headers=auth(mailbox, "read")
    ).json()
    assert [m["seq"] for m in remaining["messages"]] == [3]


def test_delete_mailbox_removes_everything(client):
    mailbox = new_mailbox(client)
    client.post(
        f"/api/mailbox/{mailbox['mailbox_id']}/messages",
        headers=auth(mailbox, "write"),
        content=b"x",
    )
    response = client.request(
        "DELETE",
        f"/api/mailbox/{mailbox['mailbox_id']}",
        headers=auth(mailbox, "read"),
    )
    assert response.status_code == 200
    assert response.json()["deleted_messages"] == 1
    after = client.get(
        f"/api/mailbox/{mailbox['mailbox_id']}", headers=auth(mailbox, "read")
    )
    assert after.status_code == 404


def test_mailbox_quota_enforced(tmp_path):
    client = make_client(tmp_path, max_messages_per_mailbox=2)
    mailbox = new_mailbox(client)
    for index in range(2):
        assert (
            client.post(
                f"/api/mailbox/{mailbox['mailbox_id']}/messages",
                headers=auth(mailbox, "write"),
                content=b"x",
            ).status_code
            == 201
        )
    overflow = client.post(
        f"/api/mailbox/{mailbox['mailbox_id']}/messages",
        headers=auth(mailbox, "write"),
        content=b"x",
    )
    assert overflow.status_code == 429
    client.__exit__(None, None, None)


def test_message_size_limit(tmp_path):
    client = make_client(tmp_path, max_blob_bytes=64)
    mailbox = new_mailbox(client)
    response = client.post(
        f"/api/mailbox/{mailbox['mailbox_id']}/messages",
        headers=auth(mailbox, "write"),
        content=b"x" * 65,
    )
    assert response.status_code == 413
    client.__exit__(None, None, None)


def test_create_rate_limit(tmp_path):
    client = make_client(tmp_path, mailbox_creates_per_hour=1)
    assert client.post("/api/mailbox").status_code == 201
    assert client.post("/api/mailbox").status_code == 429
    client.__exit__(None, None, None)


# -- prekeys --------------------------------------------------------------


def test_prekey_publish_and_consume(client):
    from noknowledge.crypto.encoding import b64e

    payload = {
        "v": 1,
        "bundle_id": b64e(b"b" * 16),
        "spk_id": 1,
        "spk": b64e(b"s" * 32),
        "spk_sig": b64e(b"g" * 64),
        "opks": [
            {"opk_id": 10, "opk": b64e(b"o" * 32)},
            {"opk_id": 11, "opk": b64e(b"p" * 32)},
        ],
    }
    assert client.post("/api/prekeys", json=payload).status_code == 201

    first = client.get(f"/api/prekeys/{payload['bundle_id']}").json()
    second = client.get(f"/api/prekeys/{payload['bundle_id']}").json()
    third = client.get(f"/api/prekeys/{payload['bundle_id']}").json()
    assert len(first["opks"]) == 1 and len(second["opks"]) == 1
    assert first["opks"][0]["opk_id"] != second["opks"][0]["opk_id"]
    assert third["opks"] == []


def test_prekey_bundle_metadata_is_public_but_identity_free(client):
    from noknowledge.crypto.encoding import b64e

    payload = {
        "v": 1,
        "bundle_id": b64e(b"b" * 16),
        "spk_id": 1,
        "spk": b64e(b"s" * 32),
        "spk_sig": b64e(b"g" * 64),
        "opks": [],
    }
    client.post("/api/prekeys", json=payload)
    got = client.get(f"/api/prekeys/{payload['bundle_id']}").json()
    assert "isign" not in got and "idh" not in got


def test_unknown_bundle_is_404(client):
    assert client.get("/api/prekeys/nope").status_code == 404


# -- blobs ----------------------------------------------------------------


def test_blob_upload_and_download(client):
    mailbox = new_mailbox(client)
    upload = client.post(
        "/api/blob",
        headers={**auth(mailbox, "write"), "X-NK-Mailbox": mailbox["mailbox_id"]},
        content=b"encrypted-bytes",
    )
    assert upload.status_code == 201
    chunk_id = upload.json()["chunk_id"]

    download = client.get(
        f"/api/blob/{chunk_id}",
        headers={**auth(mailbox, "read"), "X-NK-Mailbox": mailbox["mailbox_id"]},
    )
    assert download.status_code == 200
    assert download.content == b"encrypted-bytes"


def test_blob_is_bound_to_its_mailbox(client):
    owner = new_mailbox(client)
    other = new_mailbox(client)
    upload = client.post(
        "/api/blob",
        headers={**auth(owner, "write"), "X-NK-Mailbox": owner["mailbox_id"]},
        content=b"secret",
    )
    chunk_id = upload.json()["chunk_id"]
    response = client.get(
        f"/api/blob/{chunk_id}",
        headers={**auth(other, "read"), "X-NK-Mailbox": other["mailbox_id"]},
    )
    assert response.status_code == 404


def test_blob_upload_requires_mailbox_header(client):
    mailbox = new_mailbox(client)
    response = client.post(
        "/api/blob", headers=auth(mailbox, "write"), content=b"x"
    )
    assert response.status_code == 400


def test_blob_reupload_is_idempotent(client):
    from noknowledge.crypto.encoding import b64e

    mailbox = new_mailbox(client)
    chunk_id = b64e(b"c" * 16)
    headers = {
        **auth(mailbox, "write"),
        "X-NK-Mailbox": mailbox["mailbox_id"],
        "X-NK-Chunk": chunk_id,
    }
    assert client.post("/api/blob", headers=headers, content=b"x").status_code == 201
    assert client.post("/api/blob", headers=headers, content=b"x").status_code == 201


# -- absence of the old design -------------------------------------------


def test_no_broadcast_or_directory_endpoints(client):
    for path in (
        "/api/messages/get_messages",
        "/api/users/register",
        "/api/users/by_id/abc",
    ):
        assert client.get(path).status_code == 404