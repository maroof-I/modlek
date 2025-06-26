from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
from collections import Counter

def analyze_elasticsearch_data(es_host='http://192.168.0.109:9200', index_name='classified', request_timeout=30):
    """
    Fetch data from Elasticsearch and calculate the percentage of attacks vs normal traffic.
    
    Args:
        es_host (str): Elasticsearch host URL
        index_name (str): Name of the index to query
        request_timeout (int): Request timeout in seconds
        
    Returns:
        dict: elasticsearch response with hits containing all matching documents
    """
    try:
        es = Elasticsearch([es_host])
        
        # Use scan helper to handle large datasets
        hits = []
        for doc in scan(
            es,
            index=index_name,
            query={"query": {"match_all": {}}},
            request_timeout=request_timeout,
            preserve_order=True  # Important for consistent results
        ):
            hits.append(doc)
            
        # Format response to match expected structure
        response = {
            "hits": {
                "hits": hits,
                "total": {
                    "value": len(hits),
                    "relation": "eq"
                }
            }
        }
        
        print(f"Retrieved {len(hits)} documents from Elasticsearch")
        return response
        
    except Exception as e:
        print(f"Error in fetching Elasticsearch data: {str(e)}")
        return None
