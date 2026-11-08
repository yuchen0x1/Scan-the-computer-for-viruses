using Microsoft.Data.Sqlite;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Data.Database;

namespace PcSecurityCenter.Data.Repositories;

/// <summary>扫描记录仓储。</summary>
public class ScanRunRepository
{
    private readonly AppDatabase _db;
    public ScanRunRepository(AppDatabase db) => _db = db;

    public void Insert(ScanRunRecord r)
    {
        using var conn = _db.Open();
        AppDatabase.ExecuteNonQuery(conn, """
INSERT INTO scan_runs(id, type, started_at, finished_at, final_state, files_scanned, threats_found, engines, scope, uncovered_notes)
VALUES($id, $type, $started, $finished, $state, $files, $threats, $engines, $scope, $notes)
""",
            ("$id", r.Id.ToString()), ("$type", (int)r.Type), ("$started", r.StartedAt.ToString("O")),
            ("$finished", r.FinishedAt?.ToString("O")), ("$state", (int)r.FinalState),
            ("$files", r.FilesScanned), ("$threats", r.ThreatsFound),
            ("$engines", r.Engines), ("$scope", r.Scope), ("$notes", r.UncoveredNotes));
    }

    public List<ScanRunRecord> GetRecent(int count = 100)
    {
        using var conn = _db.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT $n";
        cmd.Parameters.AddWithValue("$n", count);
        var list = new List<ScanRunRecord>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            list.Add(new ScanRunRecord
            {
                Id = Guid.Parse(reader.GetString(0)),
                Type = (ScanType)reader.GetInt64(1),
                StartedAt = DateTime.Parse(reader.GetString(2)),
                FinishedAt = reader.IsDBNull(3) ? null : DateTime.Parse(reader.GetString(3)),
                FinalState = (ScanState)reader.GetInt64(4),
                FilesScanned = reader.GetInt64(5),
                ThreatsFound = (int)reader.GetInt64(6),
                Engines = reader.IsDBNull(7) ? "" : reader.GetString(7),
                Scope = reader.IsDBNull(8) ? "" : reader.GetString(8),
                UncoveredNotes = reader.IsDBNull(9) ? "" : reader.GetString(9),
            });
        }
        return list;
    }
}

/// <summary>威胁记录仓储。</summary>
public class ThreatRepository
{
    private readonly AppDatabase _db;
    public ThreatRepository(AppDatabase db) => _db = db;

    public void Upsert(ThreatInfo t)
    {
        using var conn = _db.Open();
        AppDatabase.ExecuteNonQuery(conn, """
INSERT INTO threats(id, scan_run_id, name, severity, kind, file_path, engine, evidence, detected_at, sha256, status, recommendation, defender_threat_id)
VALUES($id, $run, $name, $sev, $kind, $path, $engine, $ev, $at, $sha, $status, $rec, $dtid)
ON CONFLICT(id) DO UPDATE SET status=excluded.status, evidence=excluded.evidence
""",
            ("$id", t.Id.ToString()), ("$run", t.ScanRunId?.ToString()), ("$name", t.Name),
            ("$sev", (int)t.Severity), ("$kind", (int)t.Kind), ("$path", t.FilePath),
            ("$engine", t.Engine), ("$ev", t.Evidence), ("$at", t.DetectedAt.ToString("O")),
            ("$sha", t.Sha256), ("$status", (int)t.Status), ("$rec", t.Recommendation),
            ("$dtid", t.DefenderThreatId.HasValue ? t.DefenderThreatId.Value : null));
    }

    public void UpdateStatus(Guid id, ThreatStatus status)
    {
        using var conn = _db.Open();
        AppDatabase.ExecuteNonQuery(conn, "UPDATE threats SET status=$s WHERE id=$id",
            ("$s", (int)status), ("$id", id.ToString()));
    }

    public List<ThreatInfo> GetRecent(int count = 200)
    {
        using var conn = _db.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM threats ORDER BY detected_at DESC LIMIT $n";
        cmd.Parameters.AddWithValue("$n", count);
        var list = new List<ThreatInfo>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            list.Add(new ThreatInfo
            {
                Id = Guid.Parse(reader.GetString(0)),
                ScanRunId = reader.IsDBNull(1) ? null : Guid.Parse(reader.GetString(1)),
                Name = reader.GetString(2),
                Severity = (ThreatSeverity)reader.GetInt64(3),
                Kind = (DetectionKind)reader.GetInt64(4),
                FilePath = reader.GetString(5),
                Engine = reader.GetString(6),
                Evidence = reader.IsDBNull(7) ? "" : reader.GetString(7),
                DetectedAt = DateTime.Parse(reader.GetString(8)),
                Sha256 = reader.IsDBNull(9) ? "" : reader.GetString(9),
                Status = (ThreatStatus)reader.GetInt64(10),
                Recommendation = reader.IsDBNull(11) ? "" : reader.GetString(11),
                DefenderThreatId = reader.IsDBNull(12) ? null : reader.GetInt64(12),
            });
        }
        return list;
    }

    public int CountActive()
    {
        using var conn = _db.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM threats WHERE status IN (0, 1)"; // Active/Quarantined
        return Convert.ToInt32(cmd.ExecuteScalar());
    }
}

/// <summary>安全事件仓储。</summary>
public class SecurityEventRepository
{
    private readonly AppDatabase _db;
    public SecurityEventRepository(AppDatabase db) => _db = db;

    public void Insert(SecurityEvent e)
    {
        using var conn = _db.Open();
        AppDatabase.ExecuteNonQuery(conn, """
INSERT INTO security_events(id, type, severity, title, detail, created_at)
VALUES($id, $type, $sev, $title, $detail, $at)
""",
            ("$id", e.Id.ToString()), ("$type", (int)e.Type), ("$sev", (int)e.Severity),
            ("$title", e.Title), ("$detail", e.Detail), ("$at", e.CreatedAt.ToString("O")));
    }

    public List<SecurityEvent> GetRecent(int count = 100)
    {
        using var conn = _db.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM security_events ORDER BY created_at DESC LIMIT $n";
        cmd.Parameters.AddWithValue("$n", count);
        var list = new List<SecurityEvent>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            list.Add(new SecurityEvent
            {
                Id = Guid.Parse(reader.GetString(0)),
                Type = (SecurityEventType)reader.GetInt64(1),
                Severity = (ThreatSeverity)reader.GetInt64(2),
                Title = reader.GetString(3),
                Detail = reader.IsDBNull(4) ? "" : reader.GetString(4),
                CreatedAt = DateTime.Parse(reader.GetString(5)),
            });
        }
        return list;
    }

    public void CleanupOld(int days)
    {
        using var conn = _db.Open();
        AppDatabase.ExecuteNonQuery(conn, "DELETE FROM security_events WHERE created_at < $cut",
            ("$cut", DateTime.Now.AddDays(-days).ToString("O")));
    }
}

/// <summary>检查结果仓储。</summary>
public class CheckResultRepository
{
    private readonly AppDatabase _db;
    public CheckResultRepository(AppDatabase db) => _db = db;

    public void InsertBatch(string runId, IEnumerable<SecurityCheckItem> items)
    {
        using var conn = _db.Open();
        using var tx = conn.BeginTransaction();
        foreach (var i in items)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
INSERT INTO check_results(run_id, check_id, name, category, status, result, method, recommendation, checked_at)
VALUES($run, $cid, $name, $cat, $st, $res, $method, $rec, $at)
""";
            cmd.Parameters.AddWithValue("$run", runId);
            cmd.Parameters.AddWithValue("$cid", i.Id);
            cmd.Parameters.AddWithValue("$name", i.Name);
            cmd.Parameters.AddWithValue("$cat", i.Category);
            cmd.Parameters.AddWithValue("$st", (int)i.Status);
            cmd.Parameters.AddWithValue("$res", i.Result);
            cmd.Parameters.AddWithValue("$method", i.Method);
            cmd.Parameters.AddWithValue("$rec", i.Recommendation);
            cmd.Parameters.AddWithValue("$at", i.CheckedAt.ToString("O"));
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public List<SecurityCheckItem> GetLatestRun()
    {
        using var conn = _db.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
SELECT check_id, name, category, status, result, method, recommendation FROM check_results
WHERE run_id = (SELECT run_id FROM check_results ORDER BY checked_at DESC LIMIT 1)
ORDER BY category, name
""";
        var list = new List<SecurityCheckItem>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            list.Add(new SecurityCheckItem
            {
                Id = reader.GetString(0),
                Name = reader.GetString(1),
                Category = reader.GetString(2),
                Status = (CheckStatus)reader.GetInt64(3),
                Result = reader.IsDBNull(4) ? "" : reader.GetString(4),
                Method = reader.IsDBNull(5) ? "" : reader.GetString(5),
                Recommendation = reader.IsDBNull(6) ? "" : reader.GetString(6),
            });
        }
        return list;
    }
}

/// <summary>维护记录仓储。</summary>
public class MaintenanceRunRepository
{
    private readonly AppDatabase _db;
    public MaintenanceRunRepository(AppDatabase db) => _db = db;

    public void Insert(PcSecurityCenter.Core.Reporting.MaintenanceRunRecord r)
    {
        using var conn = _db.Open();
        AppDatabase.ExecuteNonQuery(conn, """
INSERT INTO maintenance_runs(id, started_at, finished_at, action, detail, freed_bytes, success)
VALUES($id, $started, $finished, $action, $detail, $freed, $success)
""",
            ("$id", r.Id.ToString()), ("$started", r.StartedAt.ToString("O")),
            ("$finished", r.FinishedAt?.ToString("O")), ("$action", r.Action),
            ("$detail", r.Detail), ("$freed", r.FreedBytes), ("$success", r.Success ? 1 : 0));
    }

    public List<PcSecurityCenter.Core.Reporting.MaintenanceRunRecord> GetRecent(int count = 100)
    {
        using var conn = _db.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM maintenance_runs ORDER BY started_at DESC LIMIT $n";
        cmd.Parameters.AddWithValue("$n", count);
        var list = new List<PcSecurityCenter.Core.Reporting.MaintenanceRunRecord>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            list.Add(new PcSecurityCenter.Core.Reporting.MaintenanceRunRecord
            {
                Id = Guid.Parse(reader.GetString(0)),
                StartedAt = DateTime.Parse(reader.GetString(1)),
                FinishedAt = reader.IsDBNull(2) ? null : DateTime.Parse(reader.GetString(2)),
                Action = reader.GetString(3),
                Detail = reader.IsDBNull(4) ? "" : reader.GetString(4),
                FreedBytes = reader.GetInt64(5),
                Success = reader.GetInt64(6) != 0,
            });
        }
        return list;
    }
}
