# Copyright 2026 CCR <chenchunrun@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Adjudication store tests (SOC adjudication loop, step 5)."""

from triage_engine.core.store import Store


def _adjudication(**over):
    record = {
        "family_id": "F-1a2b3c4d",
        "family_key": ["Tailscale远控命令注入攻击", ["CGNAT覆盖网"], ["内网"], ""],
        "name": "Tailscale远控命令注入攻击",
        "soc_verdict": "无效告警",
        "disposition": "auto_close_ok",
        "alert_ids": ["SHD-20260921-00001", "SHD-20260913-00002"],
        "applies_to_family": True,
        "days": ["20260913", "20260921"],
        "engine_route": "FAST_CLOSE",
        "adjudicator": "soc.analyst1",
        "source_worksheet": "soc_worksheet_20260921.csv",
        "notes": "opposite-label twins, ruled benign",
    }
    record.update(over)
    return record


def test_save_adjudication_upserts_by_family(store):
    returned = store.save_adjudication(_adjudication())
    assert returned == "F-1a2b3c4d"                     # PK is the family id
    row = store.get_adjudication("F-1a2b3c4d")
    assert row["soc_verdict"] == "无效告警"
    assert row["alert_ids"] == ["SHD-20260921-00001", "SHD-20260913-00002"]
    assert row["applies_to_family"] is True
    created_at = row["created_at"]

    # SOC revisits the family - upsert must keep one row, refresh updated_at
    store.save_adjudication(_adjudication(soc_verdict="有效告警", disposition="blocklist"))
    rows = store.list_adjudications()
    assert len(rows) == 1
    row = rows[0]
    assert row["soc_verdict"] == "有效告警"
    assert row["disposition"] == "blocklist"
    assert row["created_at"] == created_at
    assert row["updated_at"] >= created_at


def test_get_adjudication_miss_returns_none(store):
    assert store.get_adjudication("F-nonexist1") is None


def test_list_adjudications_filters_by_disposition(store):
    store.save_adjudication(_adjudication())
    store.save_adjudication(_adjudication(family_id="F-2b3c4d5e", disposition="monitor"))
    assert len(store.list_adjudications()) == 2
    monitored = store.list_adjudications(disposition="monitor")
    assert [r["family_id"] for r in monitored] == ["F-2b3c4d5e"]


def test_adjudication_stats(store):
    store.save_adjudication(_adjudication())
    store.save_adjudication(_adjudication(family_id="F-2b3c4d5e", soc_verdict="有效告警",
                                          disposition="blocklist"))
    stats = store.adjudication_stats()
    assert stats["total"] == 2
    assert stats["by_verdict"] == {"无效告警": 1, "有效告警": 1}
    assert stats["by_disposition"] == {"auto_close_ok": 1, "blocklist": 1}
    assert stats["member_alerts"] == 4


def test_soc_adjudication_feedback_linkage(store):
    """Import writes one append-only feedback row per member alert."""
    record = _adjudication()
    store.save_adjudication(record)
    for alert_id in record["alert_ids"]:
        store.save_feedback({
            "alert_id": alert_id,
            "feedback_type": "soc_adjudication",
            "human_verdict": record["soc_verdict"],
            "override_reason": record["disposition"],
            "payload": {"family_id": record["family_id"], "day": "20260921"},
        })
    listed = store.list_feedback(alert_id="SHD-20260921-00001")
    assert len(listed) == 1
    fb = listed[0]
    assert fb["feedback_type"] == "soc_adjudication"
    assert fb["human_verdict"] == "无效告警"
    assert fb["payload"]["family_id"] == "F-1a2b3c4d"


def test_schema_init_is_idempotent_on_existing_db(tmp_path):
    """A pre-existing DB file gains the adjudications table on next open."""
    db = str(tmp_path / "old.db")
    first = Store(db)
    first._conn.execute("DROP TABLE adjudications")   # simulate a legacy DB
    first._conn.commit()
    first.close()

    second = Store(db)
    assert second.get_adjudication("F-anything1") is None   # table recreated
    second.save_adjudication(_adjudication())
    assert second.get_adjudication("F-1a2b3c4d")["soc_verdict"] == "无效告警"
    second.close()


def test_json_fields_roundtrip_decoded(store):
    """JSON TEXT columns decode back to lists on read (payload-style)."""
    key = ["名", ["公网"], ["内网"], "d.com"]
    store.save_adjudication(_adjudication(family_key=key, days=["20260921"]))
    row = store.get_adjudication("F-1a2b3c4d")
    assert row["family_key"] == key
    assert row["days"] == ["20260921"]
