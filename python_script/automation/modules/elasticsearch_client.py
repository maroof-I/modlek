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
        
        # First, get the total count of documents
        count_query = {
            "query": {"match_all": {}}
        }
        total_count = es.count(index=index_name, body=count_query)["count"]
        print(f"Total documents in index: {total_count}")
        
        # Use scan helper to handle large datasets
        hits = []
        scroll_size = 10000  # Increased batch size
        
        # Configure scan with larger size and scroll timeout
        scan_kwargs = {
            "index": index_name,
            "query": {"query": {"match_all": {}}},
            "request_timeout": request_timeout,
            "scroll": "10m",  # Longer scroll time
            "size": scroll_size,
            "preserve_order": True
        }
        
        print("Starting document retrieval...")
        for i, doc in enumerate(scan(es, **scan_kwargs)):
            hits.append(doc)
            if (i + 1) % scroll_size == 0:
                print(f"Retrieved {i + 1} documents...")
        
        # Verify we got all documents
        if len(hits) < total_count:
            print(f"Warning: Retrieved only {len(hits)} documents out of {total_count}")
            # Try one more time with different settings if we missed documents
            remaining = total_count - len(hits)
            print(f"Attempting to retrieve remaining {remaining} documents...")
            
            # Use search after for remaining documents
            last_sort = hits[-1]["sort"] if hits and "sort" in hits[-1] else None
            if last_sort:
                search_after_query = {
                    "query": {"match_all": {}},
                    "search_after": last_sort,
                    "size": remaining
                }
                additional_docs = es.search(index=index_name, body=search_after_query)
                hits.extend(additional_docs["hits"]["hits"])
        
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
        
        print(f"Successfully retrieved {len(hits)} documents from Elasticsearch")
        if len(hits) != total_count:
            print(f"Warning: Document count mismatch. Expected {total_count}, got {len(hits)}")
        
        return response
        
    except Exception as e:
        print(f"Error in fetching Elasticsearch data: {str(e)}")
        return None
