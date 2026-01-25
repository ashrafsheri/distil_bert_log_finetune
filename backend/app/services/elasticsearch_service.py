"""
Elasticsearch Service
Handles log storage and retrieval from Elasticsearch
"""

import json
from datetime import datetime
from typing import List, Dict, Optional
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import (
    ConnectionError as ElasticsearchConnectionError,
    NotFoundError as ElasticsearchNotFoundError,
    RequestError as ElasticsearchRequestError
)
import logging

logger = logging.getLogger(__name__)

class ElasticsearchService:
    def __init__(self, host: str = "elasticsearch", port: int = 9200):
        """Initialize Elasticsearch client"""
        try:
            self.client = Elasticsearch([f"http://{host}:{port}"])
            self.index_name = "logguard-logs"
            self._create_index_if_not_exists()
        except Exception as e:
            logger.warning(f"Elasticsearch connection failed: {e}. Service will work in fallback mode.")
            self.client = None
            self.index_name = "logguard-logs"
    
    def _create_index_if_not_exists(self):
        """Create the logs index if it doesn't exist"""
        try:
            if not self.client.indices.exists(index=self.index_name):
                mapping = {
                    "mappings": {
                        "properties": {
                            "timestamp": {"type": "date"},
                            "ip_address": {"type": "ip"},
                            "api_accessed": {"type": "keyword"},
                            "status_code": {"type": "integer"},
                            "infected": {"type": "boolean"},
                            "anomaly_score": {"type": "float"},
                            "anomaly_details": {"type": "object"},
                            "raw_log": {"type": "text"},
                            "created_at": {"type": "date"}
                        }
                    }
                }
                self.client.indices.create(index=self.index_name, body=mapping)
                logger.info(f"Created Elasticsearch index: {self.index_name}")
        except (ElasticsearchConnectionError, ElasticsearchRequestError) as e:
            logger.error(f"Error creating Elasticsearch index: {e}")
    
    async def store_log(self, log_data: Dict) -> bool:
        """Store a single log entry in Elasticsearch"""
        try:
            # Add timestamp for indexing
            log_data["created_at"] = datetime.utcnow().isoformat()
            
            # Index the document
            response = self.client.index(
                index=self.index_name,
                body=log_data
            )
            
            logger.debug(f"Stored log with ID: {response['_id']}")
            return True
            
        except (ElasticsearchConnectionError, ElasticsearchRequestError) as e:
            logger.error(f"Error storing log in Elasticsearch: {e}")
            return False
    
    async def store_logs_batch(self, logs_data: List[Dict]) -> bool:
        """Store multiple log entries in Elasticsearch using bulk API"""
        if self.client is None:
            logger.warning("Elasticsearch not available, skipping log storage")
            return True
            
        try:
            bulk_body = []
            for log_data in logs_data:
                # Add timestamp for indexing
                log_data["created_at"] = datetime.utcnow().isoformat()
                
                # Add index action
                bulk_body.append({
                    "index": {
                        "_index": self.index_name
                    }
                })
                bulk_body.append(log_data)
            
            if bulk_body:
                response = self.client.bulk(body=bulk_body)
                
                if response.get("errors"):
                    logger.error(f"Some documents failed to index: {response}")
                    return False
                
                logger.info(f"Successfully stored {len(logs_data)} logs in Elasticsearch")
                return True
            
            return True
            
        except (ElasticsearchConnectionError, ElasticsearchRequestError) as e:
            logger.error(f"Error storing logs batch in Elasticsearch: {e}")
            return False
    
    async def get_logs(self, org_id: Optional[str], limit: int = 100, offset: int = 0) -> Dict:
        """Retrieve logs from Elasticsearch"""
        if self.client is None:
            logger.warning("Elasticsearch not available, returning empty logs")
            return {"logs": [], "total": 0, "offset": offset, "limit": limit}
            
        try:
            must_clauses = []
            if org_id:
                must_clauses.append({"term": {"org_id": org_id}})
            
            query = {
                "query": {
                    "bool": {
                        "must": must_clauses
                    }
                },
                "sort": [{"created_at": {"order": "desc"}}],
                "from": offset,
                "size": limit,
                "track_total_hits": True  # Ensure accurate total count beyond 10,000
            }
            
            response = self.client.search(
                index=self.index_name,
                body=query
            )
            
            logs = []
            for hit in response["hits"]["hits"]:
                log_data = hit["_source"]
                logs.append(log_data)
            
            # Get accurate total count
            total_info = response["hits"]["total"]
            if isinstance(total_info, dict):
                total = total_info["value"]
                logger.info(f"Total logs from ES: {total} (relation: {total_info.get('relation', 'eq')})")
            else:
                total = total_info
                logger.info(f"Total logs from ES: {total}")
            
            return {
                "logs": logs,
                "total": total,
                "offset": offset,
                "limit": limit
            }
            
        except (ElasticsearchConnectionError, ElasticsearchRequestError) as e:
            logger.error(f"Error retrieving logs from Elasticsearch: {e}")
            return {"logs": [], "total": 0, "offset": offset, "limit": limit}
    
    async def get_anomaly_logs(self, limit: int = 100, offset: int = 0) -> Dict:
        """Retrieve only anomaly logs from Elasticsearch"""
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"infected": True}}
                        ]
                    }
                },
                "sort": [{"created_at": {"order": "desc"}}],
                "from": offset,
                "size": limit,
                "track_total_hits": True  # Ensure accurate total count beyond 10,000
            }
            
            response = self.client.search(
                index=self.index_name,
                body=query
            )
            
            logs = []
            for hit in response["hits"]["hits"]:
                log_data = hit["_source"]
                logs.append(log_data)
            
            return {
                "logs": logs,
                "total": response["hits"]["total"]["value"],
                "offset": offset,
                "limit": limit
            }
            
        except (ElasticsearchConnectionError, ElasticsearchRequestError) as e:
            logger.error(f"Error retrieving anomaly logs from Elasticsearch: {e}")
            return {"logs": [], "total": 0, "offset": offset, "limit": limit}
    
    async def get_logs_by_ip(self, ip_address: str, limit: int = 100) -> Dict:
        """Retrieve logs for a specific IP address"""
        try:
            query = {
                "query": {
                    "term": {"ip_address": ip_address}
                },
                "sort": [{"created_at": {"order": "desc"}}],
                "size": limit,
                "track_total_hits": True  # Ensure accurate total count beyond 10,000
            }
            
            response = self.client.search(
                index=self.index_name,
                body=query
            )
            
            logs = []
            for hit in response["hits"]["hits"]:
                log_data = hit["_source"]
                logs.append(log_data)
            
            return {
                "logs": logs,
                "total": response["hits"]["total"]["value"],
                "ip_address": ip_address
            }
            
        except (ElasticsearchConnectionError, ElasticsearchRequestError) as e:
            logger.error(f"Error retrieving logs by IP from Elasticsearch: {e}")
            return {"logs": [], "total": 0, "ip_address": ip_address}
    
    async def get_stats(self) -> Dict:
        """Get log statistics from Elasticsearch"""
        try:
            # Total logs count
            total_response = self.client.count(index=self.index_name)
            total_logs = total_response["count"]
            
            # Anomaly logs count
            anomaly_query = {
                "query": {
                    "term": {"infected": True}
                }
            }
            anomaly_response = self.client.count(
                index=self.index_name,
                body=anomaly_query
            )
            anomaly_logs = anomaly_response["count"]
            
            # Normal logs count
            normal_logs = total_logs - anomaly_logs
            
            return {
                "total_logs": total_logs,
                "anomaly_logs": anomaly_logs,
                "normal_logs": normal_logs,
                "anomaly_rate": anomaly_logs / total_logs if total_logs > 0 else 0
            }
            
        except (ElasticsearchConnectionError, ElasticsearchRequestError) as e:
            logger.error(f"Error getting stats from Elasticsearch: {e}")
            return {
                "total_logs": 0,
                "anomaly_logs": 0,
                "normal_logs": 0,
                "anomaly_rate": 0
            }

    async def search_logs(
        self,
        org_id: str,
        ip: Optional[str] = None,
        api: Optional[str] = None,
        status_code: Optional[int] = None,
        infected: Optional[bool] = None,
        from_datetime: Optional[str] = None,
        to_datetime: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict:
        """Search logs with optional filters.

        Filters:
        - ip: exact match on ip_address
        - api: exact match on api_accessed (keyword)
        - status_code: exact match on status_code
        - infected: boolean match
        """
        if self.client is None:
            logger.warning("Elasticsearch not available, returning empty logs for search")
            return {"logs": [], "total": 0, "offset": offset, "limit": limit}

        try:
            must_clauses: List[Dict] = [{"term": {"org_id": org_id}}]

            if ip:
                must_clauses.append({"term": {"ip_address": ip}})
            if api:
                must_clauses.append({"term": {"api_accessed": api}})
            if status_code is not None:
                must_clauses.append({"term": {"status_code": status_code}})
            if infected is not None:
                must_clauses.append({"term": {"infected": infected}})

            range_clause: Dict = {}
            if from_datetime or to_datetime:
                range_params: Dict[str, str] = {}
                if from_datetime:
                    range_params["gte"] = from_datetime
                if to_datetime:
                    range_params["lte"] = to_datetime
                range_clause = {"range": {"timestamp": range_params}}

            query_body = {
                "query": {
                    "bool": {
                        "must": ([range_clause] if range_clause else []) + (must_clauses if must_clauses else ([{"match_all": {}}] if not range_clause else []))
                    }
                },
                "sort": [{"created_at": {"order": "desc"}}],
                "from": offset,
                "size": limit,
                "track_total_hits": True
            }

            response = self.client.search(index=self.index_name, body=query_body)

            logs: List[Dict] = []
            for hit in response["hits"]["hits"]:
                logs.append(hit["_source"])

            total_info = response["hits"]["total"]
            total = total_info["value"] if isinstance(total_info, dict) else total_info

            return {"logs": logs, "total": total, "offset": offset, "limit": limit}

        except (ElasticsearchConnectionError, ElasticsearchRequestError) as e:
            logger.error(f"Error searching logs in Elasticsearch: {e}")
            return {"logs": [], "total": 0, "offset": offset, "limit": limit}

    async def update_logs_by_ip(self, ip_address: str, infected: bool, org_id: str) -> Dict:
        """Update all logs for a specific IP address with new infected status.

        Args:
            ip_address: The IP address to update logs for
            infected: The new infected status (True for malicious, False for clean)
            org_id: Organization ID to scope the update

        Returns:
            Dict with update_count and status
        """
        if self.client is None:
            logger.warning("Elasticsearch not available, cannot update logs")
            return {"update_count": 0, "status": "error", "message": "Elasticsearch not available"}

        try:
            # Use update_by_query for better performance - updates all matching documents in one operation
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"ip_address": ip_address}},
                            {"term": {"org_id": org_id}}
                        ]
                    }
                },
                "script": {
                    "source": "ctx._source.infected = params.infected",
                    "lang": "painless",
                    "params": {
                        "infected": infected
                    }
                }
            }

            response = self.client.update_by_query(
                index=self.index_name,
                body=query,
                wait_for_completion=True,  # Wait for completion to get accurate count
                refresh=True,  # Refresh index after update
                conflicts="proceed"  # Continue on version conflicts
            )

            updated_count = response.get("updated", 0)
            failed_count = response.get("failures", 0) if "failures" in response else 0

            if failed_count > 0:
                logger.warning(f"Some documents failed to update for IP {ip_address}: {failed_count} failures")
                return {
                    "update_count": updated_count,
                    "status": "partial",
                    "message": f"Updated {updated_count} logs, {failed_count} failed"
                }

            logger.info(f"Successfully updated {updated_count} logs for IP {ip_address} with infected={infected} for org {org_id}")
            return {
                "update_count": updated_count,
                "status": "success",
                "message": f"Updated {updated_count} logs"
            }

        except (ElasticsearchConnectionError, ElasticsearchRequestError) as e:
            logger.error(f"Error updating logs by IP in Elasticsearch: {e}")
            return {"update_count": 0, "status": "error", "message": str(e)}