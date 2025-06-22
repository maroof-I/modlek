from elasticsearch import Elasticsearch
from collections import Counter

def analyze_elasticsearch_data(es_host='http://192.168.0.109:9200', index_name='classified'):
    """
    Fetch data from Elasticsearch and calculate the percentage of attacks vs normal traffic.
    
    Args:
        es_host (str): Elasticsearch host URL
        index_name (str): Name of the index to query
        
    Returns:
        dict: elasticsearch response
    """
    try:
        es = Elasticsearch([es_host])
        
        query = {
            "query": {
                "match_all": {}
            },
            "size": 10000 
        }
        
        response = es.search(
            index=index_name,
            body=query
        )
        
        return response
        
    except Exception as e:
        print(f"Error in fetching Elasticsearch data: {str(e)}")
        return None
