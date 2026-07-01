import json
import logging
import os
import subprocess
import sqlite3
import datetime
from typing import Dict, Any, Optional
from urllib.parse import quote

logger = logging.getLogger("fabric_client")
logging.basicConfig(level=logging.INFO)


def build_redis_url() -> str:
    direct_url = os.getenv("REDIS_URL")
    if direct_url:
        return direct_url

    password = os.getenv("REDIS_PASSWORD") or os.getenv("LEXLEDGER_REDIS_PASSWORD")
    host = os.getenv("REDIS_HOST", "localhost")
    port = os.getenv("REDIS_PORT", "6379")
    db = os.getenv("REDIS_DB", "0")

    if password is None:
        logger.warning(
            "REDIS_URL/REDIS_PASSWORD is not set; using unauthenticated local Redis."
        )
        return f"redis://{host}:{port}/{db}"

    return f"redis://:{quote(password, safe='')}@{host}:{port}/{db}"


REDIS_URL = build_redis_url()

class FabricClient:
    """
    Client for interacting with the Hyperledger Fabric network locally.
    Integrates Redis for caching verified clause hashes.
    If the Fabric Docker containers are not running, it automatically falls back
    to a local SQLite-based Mock Ledger to ensure application functionality.
    """
    def __init__(self, db_path: str = "mock_ledger.db"):
        self.db_path = db_path
        self.is_online = self._check_fabric_online()
        
        # Initialize Redis Cache
        self.redis_client = None
        try:
            import redis
            # Short connection timeout to prevent startup blocking
            self.redis_client = redis.from_url(REDIS_URL, socket_connect_timeout=1.0)
            self.redis_client.ping()
            logger.info("[FabricClient] Redis cache is ONLINE.")
        except Exception:
            logger.warning("[FabricClient] Redis cache is OFFLINE. Proceeding without caching.")
            self.redis_client = None

        if not self.is_online:
            logger.warning("[FabricClient] Fabric network is OFFLINE. Falling back to Mock Ledger.")
            self._init_mock_db()
        else:
            logger.info("[FabricClient] Fabric network is ONLINE. Connecting to peer container.")

    def _check_fabric_online(self) -> bool:
        """Checks if Docker is running and the Fabric 'cli' container is active."""
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", "cli"],
                capture_output=True,
                text=True,
                check=False
            )
            return result.returncode == 0 and "true" in result.stdout.lower()
        except Exception:
            return False

    def _init_mock_db(self):
        """Initializes the mock SQLite database to simulate the Fabric world state."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS world_state (
                    channel TEXT,
                    key TEXT,
                    value TEXT,
                    PRIMARY KEY (channel, key)
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS query_logs (
                    query_id TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def store_clause(self, contract_id: str, position: int, label: str, text: str, sha256_hash: str, channel: str = "lexledger-channel") -> bool:
        """Stores a clause and its hash in Fabric or the Mock Ledger."""
        self.is_online = self._check_fabric_online()

        clause_data = {
            "contract_id": str(contract_id),
            "position": int(position),
            "label": label,
            "text": text,
            "sha256_hash": sha256_hash
        }
        
        key = f"CLAUSE_{contract_id}_{label}"

        # Evict cache key to prevent stale entries
        if self.redis_client:
            try:
                cache_key = f"fabric_clause:{contract_id}:{label}"
                self.redis_client.delete(cache_key)
            except Exception:
                pass

        if self.is_online:
            try:
                args_json = json.dumps({
                    "Args": ["StoreClause", str(contract_id), str(position), label, text, sha256_hash]
                })
                cmd = [
                    "docker", "exec", "cli", "peer", "chaincode", "invoke",
                    "-o", "orderer.example.com:7050",
                    "--ordererTLSHostnameOverride", "orderer.example.com",
                    "-C", channel,
                    "-n", "clause_cc",
                    "-c", args_json,
                    "--tls",
                    "--cafile", "/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    logger.info(f"[FabricClient] Successfully stored clause {key} in channel {channel}")
                    return True
                else:
                    logger.error(f"[FabricClient] Fabric invoke failed: {result.stderr}")
            except Exception as e:
                logger.error(f"[FabricClient] Error calling Fabric: {e}")

        # Fallback Mock Ledger Write
        logger.info(f"[FabricClient][Mock] Storing clause {key} in channel {channel}")
        self._init_mock_db()
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO world_state (channel, key, value) VALUES (?, ?, ?)",
                (channel, key, json.dumps(clause_data))
            )
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"[FabricClient][Mock] Failed to write to SQLite mock ledger: {e}")
            return False
        finally:
            conn.close()

    def get_clause(self, contract_id: str, label: str, channel: str = "lexledger-channel") -> Optional[Dict[str, Any]]:
        """Retrieves a clause from Cache, Fabric, or the Mock Ledger."""
        self.is_online = self._check_fabric_online()
        key = f"CLAUSE_{contract_id}_{label}"
        cache_key = f"fabric_clause:{contract_id}:{label}"

        # 1. Check Redis Cache First
        if self.redis_client:
            try:
                cached_data = self.redis_client.get(cache_key)
                if cached_data:
                    logger.info(f"[FabricClient][Redis] Cache HIT for {key}")
                    return json.loads(cached_data)
                else:
                    logger.info(f"[FabricClient][Redis] Cache MISS for {key}")
            except Exception as e:
                logger.warning(f"[FabricClient][Redis] Cache read error: {e}")

        # 2. Query Blockchain
        clause_data = None
        if self.is_online:
            try:
                query_args = json.dumps({"Args": ["GetClause", str(contract_id), label]})
                cmd = [
                    "docker", "exec", "cli", "peer", "chaincode", "query",
                    "-C", channel,
                    "-n", "clause_cc",
                    "-c", query_args
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    output = result.stdout.strip()
                    if output:
                        clause_data = json.loads(output)
                else:
                    logger.warning(f"[FabricClient] Fabric query failed: {result.stderr.strip()}")
            except Exception as e:
                logger.error(f"[FabricClient] Error calling Fabric query: {e}")

        # 3. Query Mock Ledger Fallback
        if not clause_data:
            logger.info(f"[FabricClient][Mock] Reading clause {key} from channel {channel}")
            self._init_mock_db()
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT value FROM world_state WHERE channel = ? AND key = ?",
                    (channel, key)
                )
                row = cursor.fetchone()
                if row:
                    clause_data = json.loads(row[0])
            except Exception as e:
                logger.error(f"[FabricClient][Mock] Failed to read from SQLite mock ledger: {e}")
            finally:
                conn.close()

        # 4. Populate Cache on retrieval
        if clause_data and self.redis_client:
            try:
                self.redis_client.set(cache_key, json.dumps(clause_data), ex=300) # 5 minutes TTL
            except Exception as e:
                logger.warning(f"[FabricClient][Redis] Cache write error: {e}")

        return clause_data

    def verify_clause_hash(self, contract_id: str, label: str, current_hash: str, channel: str = "lexledger-channel") -> bool:
        """Verifies if the current hash matches the one stored on the ledger."""
        clause = self.get_clause(contract_id, label, channel)
        if not clause:
            logger.warning(f"[FabricClient] Clause {contract_id}_{label} not found on ledger for verification.")
            return False
        
        stored_hash = clause.get("sha256_hash")
        return stored_hash == current_hash

    def log_query(self, query_id: str, contract_id: str, query: str, response_hash: str, channel: str = "lexledger-channel") -> bool:
        """Logs a contract query audit event on the blockchain."""
        self.is_online = self._check_fabric_online()
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        log_data = {
            "query_id": query_id,
            "contract_id": str(contract_id),
            "query": query,
            "response_hash": response_hash,
            "timestamp": timestamp
        }

        if self.is_online:
            try:
                args_json = json.dumps({
                    "Args": ["LogQuery", query_id, str(contract_id), query, response_hash, timestamp]
                })
                cmd = [
                    "docker", "exec", "cli", "peer", "chaincode", "invoke",
                    "-o", "orderer.example.com:7050",
                    "--ordererTLSHostnameOverride", "orderer.example.com",
                    "-C", channel,
                    "-n", "clause_cc",
                    "-c", args_json,
                    "--tls",
                    "--cafile", "/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    logger.info(f"[FabricClient] Query audit log {query_id} written to Fabric.")
                    return True
                else:
                    logger.error(f"[FabricClient] Fabric log invoke failed: {result.stderr}")
            except Exception as e:
                logger.error(f"[FabricClient] Error writing log to Fabric: {e}")

        # Fallback Mock Ledger Write
        logger.info(f"[FabricClient][Mock] Logging query {query_id} to SQLite audit log.")
        self._init_mock_db()
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO query_logs (query_id, value) VALUES (?, ?)",
                (query_id, json.dumps(log_data))
            )
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"[FabricClient][Mock] Failed to log query to SQLite mock ledger: {e}")
            return False
        finally:
            conn.close()

    def get_query_log(self, query_id: str, channel: str = "lexledger-channel") -> Optional[Dict[str, Any]]:
        """Retrieves a query log from Fabric or the Mock Ledger."""
        self.is_online = self._check_fabric_online()

        if self.is_online:
            try:
                query_args = json.dumps({"Args": ["GetQueryLog", query_id]})
                cmd = [
                    "docker", "exec", "cli", "peer", "chaincode", "query",
                    "-C", channel,
                    "-n", "clause_cc",
                    "-c", query_args
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    output = result.stdout.strip()
                    if output:
                        return json.loads(output)
            except Exception as e:
                logger.error(f"[FabricClient] Error reading log from Fabric: {e}")

        # Fallback Mock Ledger Read
        self._init_mock_db()
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM query_logs WHERE query_id = ?", (query_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None
        except Exception as e:
            logger.error(f"[FabricClient][Mock] Failed to read query log: {e}")
            return None
        finally:
            conn.close()
