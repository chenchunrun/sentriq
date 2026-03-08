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

"""
User context collector for enriching alerts with user information.

This module handles collection of user context including:
- Directory information (LDAP/AD)
- User roles and permissions
- Group memberships
- Manager and organizational hierarchy
- User activity history
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from shared.utils.logger import get_logger
from shared.utils.time import utc_now, utc_now_iso

logger = get_logger(__name__)


class UserCollector:
    """
    Collector for user-related context.

    Gathers information about users from directory services
    and HR systems.
    """

    def __init__(self, cache_ttl_seconds: int = 3600):
        """
        Initialize user collector.

        Args:
            cache_ttl_seconds: Cache time-to-live in seconds (default 1 hour)
        """
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self.cache: Dict[str, tuple] = {}  # key: (data, expiry_time)

    async def collect_context(self, user_id: str) -> Dict[str, Any]:
        """
        Collect comprehensive user context.

        Args:
            user_id: User identifier (username, email, employee ID, etc.)

        Returns:
            Dictionary with user context information
        """
        # Check cache
        cache_key = f"user:{user_id}"
        cached_data = self._get_from_cache(cache_key)
        if cached_data:
            logger.debug(f"User context cache hit for {user_id}")
            return cached_data

        # Build user context
        context = {
            "user_id": user_id,
            "collected_at": utc_now_iso(),
        }

        # Query directory service
        directory_data = await self._query_directory(user_id)
        context.update(directory_data)

        # Get user groups
        groups = await self._query_groups(user_id)
        context["groups"] = groups

        # Get manager info
        manager_data = await self._query_manager(user_id)
        context["manager"] = manager_data

        # Get recent activity
        activity = await self._query_activity(user_id)
        context["recent_activity"] = activity

        # Cache the result
        self._put_in_cache(cache_key, context)

        logger.info(
            f"User context collected for {user_id}",
            extra={
                "user_id": user_id,
                "department": directory_data.get("department"),
            },
        )

        return context

    async def _query_directory(self, user_id: str) -> Dict[str, Any]:
        """
        Query directory service (LDAP/AD) for user information.

        TODO: Replace with real LDAP/AD API call.

        Real implementation should:
        - Query Active Directory via LDAP
        - Query Azure AD Graph API: https://learn.microsoft.com/en-us/graph/api/resources/user
        - Query Okta API: https://developer.okta.com/docs/reference/api/users/
        - Requires: LDAP_CONNECTION_STRING or API credentials

        Example LDAP query:
        - ldapsearch -H ldap://ldap.example.com -D "cn=admin,dc=example,dc=com" -W \
          -b "ou=users,dc=example,dc=com" "(sAMAccountName={user_id})"

        Args:
            user_id: User identifier

        Returns:
            Directory data dictionary
        """
        # Mock implementation for POC
        # Detect if user_id is email or username
        is_email = "@" in user_id

        if is_email:
            username = user_id.split("@")[0]
            email = user_id
        else:
            username = user_id
            email = f"{user_id}@example.com"

        return {
            "username": username,
            "email": email,
            "display_name": None,
            "first_name": None,
            "last_name": None,
            "title": None,
            "department": None,
            "company": None,
            "location": None,
            "office": None,
            "phone": None,
            "employee_id": None,
            "employee_type": None,
            "is_active": True,
            "last_logon": None,
            "password_last_set": None,
            "account_expires": None,
            "_mock": True,
            "_api_required": ["Active Directory/LDAP", "Azure AD", "Okta"],
        }

    async def _query_groups(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Query user group memberships.

        TODO: Replace with real directory API call.

        Real implementation should:
        - Query LDAP/AD for group memberships
        - Get nested groups if applicable
        - Requires: LDAP_CONNECTION_STRING

        Args:
            user_id: User identifier

        Returns:
            List of group dictionaries
        """
        # Mock implementation for POC
        return [
            {
                "name": "Domain Users",
                "dn": "CN=Domain Users,CN=Users,DC=example,DC=com",
                "type": "security",
                "description": "All domain users",
            }
        ]

    async def _query_manager(self, user_id: str) -> Dict[str, Any]:
        """
        Query user's manager information.

        TODO: Replace with real HR system/Directory API call.

        Real implementation should:
        - Query LDAP/AD for manager field
        - Query HR system (Workday, SAP, etc.)
        - Requires: LDAP_CONNECTION_STRING or HR_SYSTEM_API

        Args:
            user_id: User identifier

        Returns:
            Manager data dictionary
        """
        # Mock implementation for POC
        return {
            "name": None,
            "email": None,
            "title": None,
            "department": None,
            "_mock": True,
            "_api_required": ["LDAP/AD", "HR System"],
        }

    async def _query_activity(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Query recent user activity.

        TODO: Implement real activity tracking.

        Real implementation should:
        - Query SIEM for recent user activity
        - Query authentication logs
        - Query application audit logs
        - Requires: SIEM_API or LOG_ANALYTICS access

        Args:
            user_id: User identifier

        Returns:
            List of recent activity dictionaries
        """
        # Mock implementation for POC
        return []

    def _get_from_cache(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired."""
        if key in self.cache:
            data, expiry = self.cache[key]
            if utc_now() < expiry:
                return data
            else:
                del self.cache[key]
        return None

    def _put_in_cache(self, key: str, data: Any):
        """Put value in cache with expiry time."""
        expiry = utc_now() + self.cache_ttl
        self.cache[key] = (data, expiry)

    async def collect_batch_context(self, user_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Collect user context for multiple users in parallel.

        Args:
            user_ids: List of user identifiers

        Returns:
            Dictionary mapping user ID to context data
        """
        import asyncio

        tasks = [self.collect_context(user_id) for user_id in user_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        context_map = {}
        for user_id, result in zip(user_ids, results):
            if isinstance(result, Exception):
                logger.error(f"Error collecting context for {user_id}: {result}")
                context_map[user_id] = {
                    "user_id": user_id,
                    "error": str(result),
                    "collected_at": utc_now_iso(),
                }
            else:
                context_map[user_id] = result

        return context_map

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        return {
            "cache_size": len(self.cache),
            "cache_ttl_seconds": int(self.cache_ttl.total_seconds()),
            "expired_entries": sum(
                1 for _, expiry in self.cache.values()
                if utc_now() >= expiry
            ),
        }

    def clear_cache(self):
        """Clear all cached data."""
        self.cache.clear()
        logger.info("User context cache cleared")

    async def search_users(self, criteria: Dict[str, Any]) -> List[str]:
        """
        Search for users matching criteria.

        TODO: Implement real search in directory service.

        Real implementation should:
        - Query LDAP/AD search API
        - Support filters: name, department, title, location, etc.
        - Return list of matching user IDs

        Args:
            criteria: Search criteria dictionary

        Returns:
            List of user IDs matching criteria
        """
        # Mock implementation - empty result
        logger.info(f"User search called with criteria: {criteria}")
        return []

    async def get_user_peers(self, user_id: str) -> Dict[str, Any]:
        """
        Get user's peers (same team/department).

        TODO: Implement real peer lookup.

        Real implementation should:
        - Query directory service for department members
        - Exclude the user themselves
        - Return list of peer user IDs

        Args:
            user_id: User identifier

        Returns:
            Peer information dictionary
        """
        # Mock implementation
        return {
            "department_peers": [],
            "team_members": [],
            "_mock": True,
        }

    async def get_user_history(self, user_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """
        Get user's historical activity.

        TODO: Implement real history retrieval.

        Real implementation should:
        - Query SIEM for user activity over time period
        - Aggregate by type and frequency
        - Return activity summary

        Args:
            user_id: User identifier
            days: Number of days of history to retrieve

        Returns:
            List of historical activity records
        """
        # Mock implementation
        return []
