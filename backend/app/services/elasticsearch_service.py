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
    
    async def get_logs(self, limit: int = 100, offset: int = 0) -> Dict:
        """Retrieve logs from Elasticsearch"""
        if self.client is None:
            logger.warning("Elasticsearch not available, returning empty logs")
            return {"logs": [], "total": 0, "offset": offset, "limit": limit}
            
        try:
            query = {
                "query": {"match_all": {}},
                "sort": [{"created_at": {"order": "desc"}}],
                "from": offset,
                "size": limit
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
                "size": limit
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
                "size": limit
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
