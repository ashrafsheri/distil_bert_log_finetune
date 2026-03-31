"""
Elasticsearch Service
Handles log storage and retrieval from Elasticsearch
"""

import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Optional
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import (
    ConnectionError as ElasticsearchConnectionError,
    RequestError as ElasticsearchRequestError
)
import logging

logger = logging.getLogger(__name__)
ORG_ID_KEYWORD = "org_id.keyword"
INFECTED_COUNT_AGG = "infected_count"

class ElasticsearchService:
    """
    Elasticsearch Service
    Handles log storage and retrieval operations in Elasticsearch
    """
    
    def __init__(self, host: str = "elasticsearch", port: int = 9200):
        """
        Initialize Elasticsearch client
        
        Args:
            host: Elasticsearch host address
            port: Elasticsearch port number
            
        Returns:
            None
        """
        try:
            self.client = Elasticsearch([f"http://{host}:{port}"])
            self.index_name = "logguard-logs"
            self._create_index_if_not_exists()
        except Exception as e:
            logger.warning(f"Elasticsearch connection failed: {e}. Service will work in fallback mode.")
            self.client = None
            self.index_name = "logguard-logs"


    def _create_index_if_not_exists(self):
        """
        Create the logs index if it doesn't exist
        
        Returns:
            None
        """
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

    @staticmethod
    def _extract_total_hits(response: Dict) -> int:
        total_info = response["hits"]["total"]
        return total_info["value"] if isinstance(total_info, dict) else total_info

    @staticmethod
    def _extract_infected_count(response: Dict) -> int:
        return response.get("aggregations", {}).get(INFECTED_COUNT_AGG, {}).get("doc_count", 0)


    async def store_log(self, log_data: Dict) -> bool:
        """Store a single log entry in Elasticsearch"""
        try:
            # Add timestamp for indexing
            log_data["created_at"] = datetime.now(timezone.utc).isoformat()
            
            # Index the document
            response = await asyncio.to_thread(
                self.client.index,
                index=self.index_name,
                body=log_data,
            )
            
            logger.debug(f"Stored log with ID: {response['_id']}")
            return True
            
        except (ElasticsearchConnectionError, ElasticsearchRequestError) as e:
            logger.error(f"Error storing log in Elasticsearch: {e}")
            return False


    async def store_logs_batch(self, logs_data: List[Dict]) -> bool:
        """
        Store multiple log entries in Elasticsearch using bulk API
        
        Args:
            logs_data: List of log dictionaries to store
            
        Returns:
            True if successful, False otherwise
        """
        logger.debug(f"[ES] store_logs_batch called with {len(logs_data)} logs")
        
        if self.client is None:
            logger.warning("Elasticsearch not available, skipping log storage")
            logger.debug("[ES] Client is None, skipping storage")
            return True
            
        try:
            bulk_body = []
            for log_data in logs_data:
                # Add timestamp for indexing
                log_data["created_at"] = datetime.now(timezone.utc).isoformat()
                
                # Add index action
                bulk_body.append({
                    "index": {
                        "_index": self.index_name
                    }
                })
                bulk_body.append(log_data)
            
            if bulk_body:
                logger.debug(f"[ES] Sending bulk request with {len(bulk_body)//2} documents to index {self.index_name}")
                response = await asyncio.to_thread(self.client.bulk, body=bulk_body)
                
                if response.get("errors"):
                    logger.error(f"Some documents failed to index: {response}")
                    logger.debug(f"[ES] Bulk errors: {response}")
                    return False
                
                logger.debug(f"[ES] Successfully indexed {len(bulk_body)//2} documents")
                logger.info(f"Successfully stored {len(logs_data)} logs in Elasticsearch")
                return True
            
            return True
            
        except (ElasticsearchConnectionError, ElasticsearchRequestError) as e:
            logger.error(f"Error storing logs batch in Elasticsearch: {e}")
            return False


    async def get_logs(self, org_id: Optional[str], limit: int = 100, offset: int = 0) -> Dict:
        """
        Retrieve logs from Elasticsearch
        
        Args:
            org_id: Organization ID to filter logs
            limit: Maximum number of logs to return
            offset: Number of logs to skip
            
        Returns:
            Dictionary containing logs and pagination info
        """
        if self.client is None:
            logger.warning("Elasticsearch not available, returning empty logs")
            return {"logs": [], "total": 0, "infected_count": 0, "offset": offset, "limit": limit}
            
        try:
            must_clauses = []
            if org_id:
                must_clauses.append({"term": {ORG_ID_KEYWORD: org_id}})
            
            query = {
                "query": {
                    "bool": {
                        "must": must_clauses
                    }
                },
                "aggs": {
                    INFECTED_COUNT_AGG: {
                        "filter": {
                            "term": {"infected": True}
                        }
                    }
                },
                "sort": [{"created_at": {"order": "desc"}}],
                "from": offset,
                "size": limit,
                "track_total_hits": True  # Ensure accurate total count beyond 10,000
            }
            
            response = await asyncio.to_thread(
                self.client.search,
                index=self.index_name,
                body=query,
            )
            
            logs = []
            for hit in response["hits"]["hits"]:
                log_data = hit["_source"]
                logs.append(log_data)
            
            # Get accurate total count
            total = self._extract_total_hits(response)
            infected_count = self._extract_infected_count(response)
            logger.info("Total logs from ES: %s, infected logs: %s", total, infected_count)
            
            return {
                "logs": logs,
                "total": total,
                "infected_count": infected_count,
                "offset": offset,
                "limit": limit
            }
            
        except (ElasticsearchConnectionError, ElasticsearchRequestError) as e:
            logger.error(f"Error retrieving logs from Elasticsearch: {e}")
            return {"logs": [], "total": 0, "infected_count": 0, "offset": offset, "limit": limit}
    

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
            return {"logs": [], "total": 0, "infected_count": 0, "offset": offset, "limit": limit}

        try:
            must_clauses: List[Dict] = [{"term": {ORG_ID_KEYWORD: org_id}}]

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

            query_filters: List[Dict] = list(must_clauses)
            if range_clause:
                query_filters.append(range_clause)

            query_body = {
                "query": {
                    "bool": {
                        "must": query_filters
                    }
                },
                "aggs": {
                    INFECTED_COUNT_AGG: {
                        "filter": {
                            "term": {"infected": True}
                        }
                    }
                },
                "sort": [{"created_at": {"order": "desc"}}],
                "from": offset,
                "size": limit,
                "track_total_hits": True
            }

            response = await asyncio.to_thread(
                self.client.search,
                index=self.index_name,
                body=query_body,
            )

            logs: List[Dict] = []
            for hit in response["hits"]["hits"]:
                logs.append(hit["_source"])

            total = self._extract_total_hits(response)
            infected_count = self._extract_infected_count(response)

            return {
                "logs": logs,
                "total": total,
                "infected_count": infected_count,
                "offset": offset,
                "limit": limit,
            }

        except (ElasticsearchConnectionError, ElasticsearchRequestError) as e:
            logger.error(f"Error searching logs in Elasticsearch: {e}")
            return {"logs": [], "total": 0, "infected_count": 0, "offset": offset, "limit": limit}


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
                            {"term": {ORG_ID_KEYWORD: org_id}}
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

            response = await asyncio.to_thread(
                self.client.update_by_query,
                index=self.index_name,
                body=query,
                wait_for_completion=True,
                refresh=True,
                conflicts="proceed",
            )

            updated_count = response.get("updated", 0)
            failures = response.get("failures", [])
            failed_count = len(failures)

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
