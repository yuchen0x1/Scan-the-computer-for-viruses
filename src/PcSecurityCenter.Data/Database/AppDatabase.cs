using Microsoft.Data.Sqlite;

namespace PcSecurityCenter.Data.Database;

/// <summary>
/// SQLite 数据库访问。WAL 模式 + 架构版本迁移（schema_version 表）。
/// 所有仓储共享单连接工厂（线程安全：每次操作独立连接，SQLite 文件锁由 WAL 缓解）。
/// </summary>
public class AppDatabase : IDisposable
{
    private readonly string _connectionString;
    private const int CurrentSchemaVersion = 1;

    public AppDatabase(string dbPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(dbPath)!);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
        }.ToString();
        Initialize();
    }

    public SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        return conn;
    }

    private void Initialize()
    {
        using var conn = Open();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;";
            cmd.ExecuteNonQuery();
        }
        using var tx = conn.BeginTransaction();

        Execute(conn, tx, """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);
""");
        var v = 0;
        using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "SELECT version FROM schema_version";
            var r = cmd.ExecuteScalar();
            if (r != null) v = Convert.ToInt32(r);
        }

        Execute(conn, tx, """
CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    type INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    final_state INTEGER NOT NULL,
    files_scanned INTEGER NOT NULL,
    threats_found INTEGER NOT NULL,
    engines TEXT,
    scope TEXT,
    uncovered_notes TEXT
);
CREATE TABLE IF NOT EXISTS threats (
    id TEXT PRIMARY KEY,
    scan_run_id TEXT,
    name TEXT NOT NULL,
    severity INTEGER NOT NULL,
    kind INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    engine TEXT NOT NULL,
    evidence TEXT,
    detected_at TEXT NOT NULL,
    sha256 TEXT,
    status INTEGER NOT NULL,
    recommendation TEXT,
    defender_threat_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_threats_time ON threats(detected_at);
CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY,
    type INTEGER NOT NULL,
    severity INTEGER NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_time ON security_events(created_at);
CREATE TABLE IF NOT EXISTS check_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    check_id TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    status INTEGER NOT NULL,
    result TEXT,
    method TEXT,
    recommendation TEXT,
    checked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS maintenance_runs (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    action TEXT NOT NULL,
    detail TEXT,
    freed_bytes INTEGER NOT NULL DEFAULT 0,
    success INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
""");

        if (v < CurrentSchemaVersion)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = v == 0
                ? "INSERT INTO schema_version(version) VALUES($v);"
                : "UPDATE schema_version SET version=$v;";
            cmd.Parameters.AddWithValue("$v", CurrentSchemaVersion);
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    private static void Execute(SqliteConnection conn, SqliteTransaction tx, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    public static long ExecuteNonQuery(SqliteConnection conn, string sql, params (string name, object? value)[] ps)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (name, value) in ps)
            cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return cmd.ExecuteNonQuery();
    }

    /// <summary>连接按操作打开/关闭，Dispose 仅用于显式清理（当前无持久连接）。</summary>
    public void Dispose() => GC.SuppressFinalize(this);
}
