import json
from datetime import datetime
from typing import Any, Dict, List, Optional
import aiosqlite
from app.storage.database import db_manager


class AuditRepository:
    """Handles persistence and retrieval of security events and performance telemetry."""

    @staticmethod
    async def create_log(
        log_id: str,
        client_id: str,
        model: str,
        action: str,
        risk_score: float,
        latency_ms: float,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        request_prompt: Optional[str] = None,
        sanitized_prompt: Optional[str] = None,
        raw_response: Optional[str] = None,
        sanitized_response: Optional[str] = None,
        violations: Optional[List[Dict[str, Any]]] = None,
        inspector_details: Optional[Dict[str, Any]] = None,
        client_ip: Optional[str] = None,
    ) -> None:
        violations_json = json.dumps(violations or [])
        inspector_details_json = json.dumps(inspector_details or {})

        sql = """
        INSERT INTO audit_logs (
            id, client_id, model, action, risk_score, latency_ms,
            prompt_tokens, completion_tokens, request_prompt, sanitized_prompt,
            raw_response, sanitized_response, violations_json,
            inspector_details_json, client_ip
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        async with db_manager.get_connection() as db:
            await db.execute(
                sql,
                (
                    log_id,
                    client_id,
                    model,
                    action,
                    risk_score,
                    latency_ms,
                    prompt_tokens,
                    completion_tokens,
                    request_prompt,
                    sanitized_prompt,
                    raw_response,
                    sanitized_response,
                    violations_json,
                    inspector_details_json,
                    client_ip,
                ),
            )
            await db.commit()

    @staticmethod
    async def get_recent_logs(
        limit: int = 50,
        offset: int = 0,
        action: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        conditions = []
        params = []

        if action and action != "ALL":
            conditions.append("action = ?")
            params.append(action)

        if search:
            conditions.append("(id LIKE ? OR client_id LIKE ? OR request_prompt LIKE ? OR violations_json LIKE ?)")
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param, search_param])

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"""
        SELECT id, timestamp, client_id, model, action, risk_score, latency_ms,
               prompt_tokens, completion_tokens, request_prompt, sanitized_prompt,
               raw_response, sanitized_response, violations_json, inspector_details_json, client_ip
        FROM audit_logs
        {where_clause}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        async with db_manager.get_connection() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(sql, params)
            rows = await cursor.fetchall()
            logs = []
            for row in rows:
                item = dict(row)
                item["violations"] = json.loads(item["violations_json"] or "[]")
                item["inspector_details"] = json.loads(item["inspector_details_json"] or "{}")
                logs.append(item)
            return logs

    @staticmethod
    async def get_log_by_id(log_id: str) -> Optional[Dict[str, Any]]:
        sql = "SELECT * FROM audit_logs WHERE id = ?"
        async with db_manager.get_connection() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(sql, (log_id,))
            row = await cursor.fetchone()
            if not row:
                return None
            item = dict(row)
            item["violations"] = json.loads(item["violations_json"] or "[]")
            item["inspector_details"] = json.loads(item["inspector_details_json"] or "{}")
            return item

    @staticmethod
    async def get_metrics_summary() -> Dict[str, Any]:
        """Aggregate security statistics, block rates, and violation breakdown."""
        async with db_manager.get_connection() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT 
                    COUNT(*) as total_requests,
                    SUM(CASE WHEN action = 'BLOCKED' THEN 1 ELSE 0 END) as blocked_count,
                    SUM(CASE WHEN action = 'REDACTED' THEN 1 ELSE 0 END) as redacted_count,
                    SUM(CASE WHEN action = 'FLAGGED' THEN 1 ELSE 0 END) as flagged_count,
                    SUM(CASE WHEN action = 'ALLOW' THEN 1 ELSE 0 END) as allowed_count,
                    AVG(latency_ms) as avg_latency_ms,
                    AVG(risk_score) as avg_risk_score
                FROM audit_logs
            """)
            stats = dict(await cursor.fetchone())

            total = stats["total_requests"] or 0
            blocked = stats["blocked_count"] or 0
            block_rate = (blocked / total * 100) if total > 0 else 0.0

            cursor = await db.execute("""
                SELECT violations_json FROM audit_logs WHERE violations_json != '[]' AND violations_json IS NOT NULL
            """)
            violation_rows = await cursor.fetchall()
            category_counts = {"prompt_injection": 0, "pii": 0, "secret_leakage": 0, "other": 0}
            for v_row in violation_rows:
                try:
                    viols = json.loads(v_row[0])
                    for v in viols:
                        cat = v.get("category", "other")
                        if cat in category_counts:
                            category_counts[cat] += 1
                        else:
                            category_counts["other"] += 1
                except Exception:
                    pass

            return {
                "total_requests": total,
                "blocked_count": blocked,
                "redacted_count": stats["redacted_count"] or 0,
                "flagged_count": stats["flagged_count"] or 0,
                "allowed_count": stats["allowed_count"] or 0,
                "block_rate_percent": round(block_rate, 2),
                "avg_latency_ms": round(stats["avg_latency_ms"] or 0.0, 2),
                "avg_risk_score": round(stats["avg_risk_score"] or 0.0, 3),
                "threat_breakdown": category_counts,
            }
