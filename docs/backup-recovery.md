# AgentGuard — Database Backup & Recovery Guide

## 1. PostgreSQL Backup Strategy

AgentGuard persists security scan history and results in PostgreSQL (`scans` table). To ensure business continuity and disaster recovery, production deployments must establish automated database backups.

### Recommended Backup Tools
- **`pg_dump`**: Logical backups suitable for small to medium installations (< 100 GB).
- **`pg_backrest` / AWS RDS Snapshots**: Physical/snapshot backups suitable for high-throughput enterprise deployments with point-in-time recovery (PITR).

### Backup Schedule Guidelines

| Type | Frequency | Retention | Target Recovery Time (RTO) | Target Data Loss (RPO) |
|---|---|---|---|---|
| **Daily Logical Backup** | Every 24 hours (02:00 UTC) | 30 days | `< 30 minutes` | `< 24 hours` |
| **Hourly Transaction Logs (WAL)** | Every 60 minutes | 7 days | `< 15 minutes` | `< 1 hour` |
| **Pre-Upgrade Snapshot** | Before any schema migration | Until deployment verified | `< 10 minutes` | `0 seconds` |

---

## 2. Backup Execution Procedures

### 2.1 Logical Backup via `pg_dump`

```bash
# Export schema and scan records to compressed custom format file
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME -F c -b -v -f "/backups/agentguard_$(date +%Y%m%d_%H%M%S).dump"
```

### 2.2 Containerized Docker Backup

```bash
docker exec -t agentguard-postgres pg_dump -U agentguard -d agentguard -F c > backup.dump
```

---

## 3. Disaster Recovery & Restore Procedures

### 3.1 Restoring to a Clean Database

1. Ensure the PostgreSQL database service is running and accessible.
2. Terminate active application connections to prevent write conflicts:
   ```sql
   SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'agentguard' AND pid <> pg_backend_pid();
   ```
3. Restore database schema and scan records:
   ```bash
   pg_restore -h $DB_HOST -U $DB_USER -d $DB_NAME --clean --if-exists -v backup.dump
   ```
4. Verify table integrity:
   ```sql
   SELECT count(*) FROM scans;
   ```
5. Restart AgentGuard API service:
   ```bash
   curl -f http://localhost:8000/health/ready
   ```

---

## 4. Scan History Schema Recovery

The AgentGuard PostgreSQL schema is managed automatically on service startup via `init_db()`.
If table corruption occurs:
1. Re-initialize empty schema: `python -c "from app.repositories import init_db; from sqlalchemy import create_engine; init_db(create_engine('$DATABASE_URL'))"`
2. Re-import logical dump via `pg_restore`.
