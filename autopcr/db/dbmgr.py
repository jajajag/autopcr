import os, json, re
from typing import Dict, Iterable, Optional, Pattern, Tuple
from ..constants import CACHE_DIR, DATA_DIR
from .assetmgr import assetmgr
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from ..util.logger import instance as logger

# rainbow 表项中指向真实表名的特殊键
TABLE_NAME_KEY = "--table_name"

# 哈希名的形态：表名 = 'v1_' + sha256 十六进制，列名 = sha256 十六进制
HASHED_NAME = re.compile(r"(?:v1_)?[0-9a-f]{64}")

class dbmgr:
    def __init__(self, region: str = 'cn'):
        self.region = region
        self.ver = None
        self.generation = 0
        self._dbpath = None
        self._engine = None

    async def update_db(self, mgr: assetmgr):
        ver = mgr.ver
        self._dbpath = os.path.join(CACHE_DIR, 'db', f'{ver}.db')
        if not os.path.exists(self._dbpath):
            data = await mgr.db()
            # 先写临时文件再原子改名，避免中途被打断时在最终路径上留下半截库
            # 后缀不能是 .db，否则会被 db_start 的 glob 当成一个可用版本挑走
            tmppath = f'{self._dbpath}.{os.getpid()}.tmp'
            try:
                with open(tmppath, 'wb') as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmppath, self._dbpath)
            except OSError:
                # 并发下别的进程可能已经落好同一版本，有完整的库可用就不必失败
                if not os.path.exists(self._dbpath):
                    raise
                logger.warning(f'db version {ver} was provided by another process')
            finally:
                if os.path.exists(tmppath):
                    os.remove(tmppath)
            logger.info(f'db version {ver} updated')
        self.dispose()
        self._engine = create_engine(f'sqlite:///{self._dbpath}')
        self.ver = ver
        self.unhash()
        self.generation += 1

    def load_db(self, path: str, ver: int):
        """Load an already decoded database, including regional mirrors."""
        self.dispose()
        self._dbpath = path
        self._engine = create_engine(f'sqlite:///{self._dbpath}')
        self.ver = int(ver)
        self.generation += 1

    def dispose(self):
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None

    def session(self) -> Session:
        return Session(self._engine)

    @staticmethod
    def _build_replacer(rainbow: dict) -> Tuple[Dict[str, str], Pattern]:
        # 表名与列名可以合并进同一个映射：哈希名全局唯一
        mapping: Dict[str, str] = {}
        for hashed_table, cols in rainbow.items():
            intact_table = cols.get(TABLE_NAME_KEY)
            if intact_table:
                mapping[hashed_table] = intact_table
            for hashed_col, intact_col in cols.items():
                if hashed_col != TABLE_NAME_KEY:
                    mapping[hashed_col] = intact_col
        mapping = {hashed: intact for hashed, intact in mapping.items() if hashed != intact}

        # 定长正则扫描 + 查表比上万个字面量拼成的 alternation 快两个数量级，形态不符则退回后者
        if all(HASHED_NAME.fullmatch(hashed) for hashed in mapping):
            return mapping, HASHED_NAME
        pattern = "|".join(sorted((re.escape(hashed) for hashed in mapping), key=len, reverse=True))
        return mapping, re.compile(pattern)

    def unhash(
        self,
        rainbow_json: Optional[str] = None,
        *,
        strict: bool = False,
        required_tables: Iterable[str] = (),
    ) -> int:
        rainbow_json = rainbow_json or os.path.join(DATA_DIR, 'rainbow.json')
        if not os.path.exists(rainbow_json):
            message = f"Rainbow table not found: {rainbow_json}"
            if strict:
                raise FileNotFoundError(message)
            logger.error("%s; unhashing skipped.", message)
            return 0

        with open(rainbow_json, 'r', encoding='utf-8') as f:
            rainbow = json.load(f)
        if strict:
            for hashed_table, columns in rainbow.items():
                if not isinstance(columns, dict):
                    raise ValueError(f'Invalid rainbow entry: {hashed_table!r}')
                identifiers = [
                    hashed_table,
                    *(name for name in columns if name != TABLE_NAME_KEY),
                    *columns.values(),
                ]
                if any(
                    not isinstance(name, str)
                    or not re.fullmatch(r'[A-Za-z0-9_]+', name)
                    for name in identifiers
                ):
                    raise ValueError(
                        f'Invalid identifier in rainbow entry {hashed_table!r}'
                    )
        mapping, pattern = self._build_replacer(rainbow)

        def restore(text):
            if not text:
                return text
            return pattern.sub(lambda m: mapping.get(m.group(0), m.group(0)), text)

        logger.info("Start Unhashing DB with %s.", rainbow_json)
        with self._engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            schema_version = conn.exec_driver_sql("PRAGMA schema_version").scalar()
            rows = conn.exec_driver_sql(
                "SELECT rowid, type, name, tbl_name, sql FROM sqlite_master"
            ).fetchall()

            # 只改 schema 文本，不搬运数据行，故索引、触发器、视图原样保留；
            # rainbow 未覆盖的表/列不在映射里，自然保持原名
            updates = []
            renamed_tables = 0
            unresolved_tables = 0
            restored_table_names = set()
            for rowid, type_, name, tbl_name, sql in rows:
                restored = (restore(name), restore(tbl_name), restore(sql))
                if type_ == 'table':
                    restored_table_names.add(restored[0])
                    if HASHED_NAME.fullmatch(restored[0]):
                        unresolved_tables += 1
                if restored == (name, tbl_name, sql):
                    continue
                updates.append((*restored, rowid))
                if type_ == 'table' and restored[0] != name:
                    renamed_tables += 1

            minimum_coverage = max(1, len(rainbow) * 4 // 5)
            missing_required = [
                table for table in required_tables
                if table not in restored_table_names
            ]
            if strict and renamed_tables < minimum_coverage:
                raise ValueError(
                    "Rainbow table coverage is too low: "
                    f"decoded {renamed_tables}/{len(rainbow)} tables"
                )
            if missing_required:
                raise ValueError(
                    "Decoded database is missing required tables: "
                    + ", ".join(missing_required)
                )
            if unresolved_tables:
                logger.warning(f"{unresolved_tables} tables missing from rainbow table, left hashed.")

            if not updates:
                logger.info("DB is already unhashed, nothing to do.")
                return 0

            try:
                conn.exec_driver_sql("PRAGMA writable_schema=ON")
                conn.exec_driver_sql("BEGIN")
                conn.exec_driver_sql(
                    "UPDATE sqlite_master SET name=?, tbl_name=?, sql=? WHERE rowid=?", updates
                )
                conn.exec_driver_sql("COMMIT")
                # 直改 sqlite_master 不会更新库头的 schema cookie，手动 +1 让后续连接重载 schema
                conn.exec_driver_sql(f"PRAGMA schema_version={schema_version + 1}")
                # RESET 让当前连接立刻重载，需要 SQLite >= 3.32，老版本报错也无妨
                try:
                    conn.exec_driver_sql("PRAGMA writable_schema=RESET")
                except Exception:
                    pass
            finally:
                conn.exec_driver_sql("PRAGMA writable_schema=OFF")

            # sqlite_stat1 里记的还是旧哈希名，统计已失效，按真实名重建
            conn.exec_driver_sql("ANALYZE")

        # 连接池里可能还留着 schema 已过期的连接
        self._engine.dispose()
        logger.info(f"Unhashing complete, {renamed_tables} tables restored.")
        return renamed_tables


_instances = {'cn': dbmgr('cn')}


def get_dbmgr(region: str = 'cn') -> dbmgr:
    if region not in _instances:
        _instances[region] = dbmgr(region)
    return _instances[region]


instance = get_dbmgr('cn')
