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

"""Temporal workflow definitions for the workflow engine."""

from datetime import timedelta
from typing import Any, Dict, List

from temporalio import activity, workflow


@activity.defn
async def execute_step_activity(step: Dict[str, Any], input_data: Dict[str, Any]) -> Dict[str, Any]:
    """Minimal step activity executed by Temporal workers."""
    return {
        "step": step.get("name"),
        "type": step.get("type"),
        "service": step.get("service"),
        "status": "completed",
        "input_keys": sorted(list(input_data.keys())),
    }


@workflow.defn
class SecurityWorkflow:
    """Temporal-backed security workflow."""

    @workflow.run
    async def run(
        self,
        workflow_id: str,
        execution_id: str,
        steps: List[Dict[str, Any]],
        input_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        results = []
        for step in steps:
            result = await workflow.execute_activity(
                execute_step_activity,
                args=[step, input_data],
                start_to_close_timeout=timedelta(seconds=30),
            )
            results.append(result)

        return {
            "workflow_id": workflow_id,
            "execution_id": execution_id,
            "status": "completed",
            "steps": results,
        }
