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

"""Policy Engine tests (requirement §25/§26) - LLM never owns execution."""

from triage_engine.core.policy import APPROVAL_REQUIRED, AUTO, MANUAL, evaluate_action


def test_whitelisted_auto_action():
    d = evaluate_action("close_false_positive")
    assert d.mode == AUTO
    assert d.approver_required is False


def test_high_risk_action_requires_approval():
    for action in ("disable_account", "isolate_host", "kill_process", "block_ip",
                   "firewall_change", "delete_file", "stop_service"):
        d = evaluate_action(action)
        assert d.mode == APPROVAL_REQUIRED
        assert d.approver_required is True


def test_critical_asset_escalates_auto_to_approval():
    state = {"asset": {"asset_criticality": "critical"}}
    verdict = {"verdict": "MALICIOUS"}
    d = evaluate_action("reprioritize_alert", verdict=verdict, state=state)
    assert d.mode == APPROVAL_REQUIRED
    assert "critical_asset" in d.reasons


def test_unknown_action_is_manual_not_silent_deny():
    d = evaluate_action("reboot_datacenter")
    assert d.mode == MANUAL
