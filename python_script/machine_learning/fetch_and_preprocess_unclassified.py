import pandas as pd
import numpy as np
from datetime import datetime, timezone
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan, bulk
import joblib
from modules.data_preprocessor import preprocess_http_data, standardize_column_names
from modules.user_agent_processor import process_user_agent_features
from modules.text_processor import create_tfidf_vectors, preprocess_text

# --- CONFIGURATION ---
ES_HOST = 'http://192.168.0.109:9200'  # Change if needed

def fetch_elasticsearch_data(index_pattern, size=10000):
    """Fetch all documents from the given index pattern."""
    es = Elasticsearch(ES_HOST)
    results = []
    original_docs = []  # Store complete original documents
    
    query = {
        "query": {
            "match_all": {}
        }
    }
    
    for doc in scan(es, index=index_pattern, query=query, size=size):
        source = doc.get('_source', {})
        # Store the complete original document
        original_docs.append(source)
        
        # Extract only the fields needed for classification
        processed_doc = {
            'http_method': source.get('http_method', '').upper(),
            'request_path': source.get('request_path', '/'),
            'request_body': source.get('request_body', ''),
            'user_agent': source.get('user_agent', 'Unknown'),
            'content_length': source.get('content_length', 0),
            'transaction_id': source.get('transaction_id', '')
        }
        results.append(processed_doc)
    
    return pd.DataFrame(results), original_docs

def preprocess_unclassified_data(df):
    """Preprocess data to match the training data format."""
    print("Starting preprocessing...")
    print(f"Initial shape: {df.shape}")
    
    # Standardize column names
    df = standardize_column_names(df)
    print("Standardized column names")
    
    # Preprocess HTTP data
    df = preprocess_http_data(df)
    print("Preprocessed HTTP data")
    
    # Process user agent features
    ua_features = process_user_agent_features(df)
    df = pd.concat([df, ua_features], axis=1)
    df = df.drop(columns=['user_agent'])
    print("Processed user agent features")
    
    # Process HTTP method (keeping uppercase to match training data)
    http_method_dummies = pd.get_dummies(df['http_method'], prefix='http_method')
    df = pd.concat([df, http_method_dummies], axis=1)
    df = df.drop(columns=['http_method'])
    print("Processed HTTP method")
    
    # Process request body with TF-IDF
    print("Processing request bodies...")
    body_texts = df["request_body"].fillna('').astype(str)
    # Ensure there's at least some content and preprocess
    body_texts = body_texts.apply(lambda x: preprocess_text('empty_body') if x.strip() == '' else preprocess_text(x))
    body_vectors, _ = create_tfidf_vectors(
        body_texts, 
        max_features=100,
        verbose=True,
        batch_size=500,
        min_df=1,  # Lower min_df to handle sparse data
        max_df=1.0  # Higher max_df to keep all terms
    )
    body_feature_names = [f'body_tfidf_{i}' for i in range(body_vectors.shape[1])]
    body_features = pd.DataFrame(body_vectors, columns=body_feature_names, index=df.index)
    df = pd.concat([df, body_features], axis=1)
    df = df.drop(columns=['request_body'])
    print("Processed request bodies")
    
    # Process request paths with TF-IDF
    print("Processing request paths...")
    path_texts = df["request_path"].fillna('/').astype(str)
    path_texts = path_texts.apply(preprocess_text)
    path_vectors, _ = create_tfidf_vectors(
        path_texts, 
        max_features=100,
        verbose=True,
        batch_size=500,
        min_df=1,  # Lower min_df to handle sparse data
        max_df=1.0  # Higher max_df to keep all terms
    )
    path_feature_names = [f'path_tfidf_{i}' for i in range(path_vectors.shape[1])]
    path_features = pd.DataFrame(path_vectors, columns=path_feature_names, index=df.index)
    df = pd.concat([df, path_features], axis=1)
    df = df.drop(columns=['request_path'])
    print("Processed request paths")
    
    # Convert boolean columns to int
    bool_cols = df.select_dtypes(include=['bool']).columns
    for col in bool_cols:
        df[col] = df[col].astype(int)
    
    # Keep track of transaction IDs
    transaction_ids = df['transaction_id'] if 'transaction_id' in df.columns else None
    if 'transaction_id' in df.columns:
        df = df.drop(columns=['transaction_id'])
    
    print(f"Final shape: {df.shape}")
    return df, transaction_ids

def classify_and_send_to_elastic(df, transaction_ids, original_docs, model_path="random_forest_trained.joblib"):
    """Classify the preprocessed data and send it back to Elasticsearch with all original fields."""
    # Load the model
    clf = joblib.load(model_path)
    
    # Get the feature names the model was trained on
    expected_features = clf.feature_names_in_
    
    # Ensure all expected features exist in the dataframe
    for feature in expected_features:
        if feature not in df.columns:
            print(f"Adding missing feature: {feature}")
            df[feature] = 0
    
    # Only keep the features the model knows about for prediction
    prediction_df = df[expected_features]
    
    # Make predictions
    predictions = clf.predict(prediction_df)
    
    # Create the classified index name
    time_utc = datetime.now(timezone.utc)
    classified_index = f"classified_{time_utc.strftime('%Y.%m.%d.%H')}"
    
    # Prepare documents for bulk indexing
    actions = []
    for pred, original_doc in zip(predictions, original_docs):
        # Create a new document with all original fields
        doc = {
            '_index': classified_index,
            '_source': original_doc  # Include all original fields
        }
        
        # Add classification-specific fields
        doc['_source'].update({
            'target': int(pred),
            'classification_timestamp': time_utc.isoformat()
        })
        
        actions.append(doc)
    
    # Send to Elasticsearch
    es = Elasticsearch(ES_HOST)
    success, failed = bulk(es, actions)
    
    return {
        'classified_index': classified_index,
        'total_documents': len(predictions),
        'successful': success,
        'failed': failed
    }

if __name__ == "__main__":
    # Example usage
    time_utc = datetime.now(timezone.utc).strftime('%Y.%m.%d.%H')
    index_pattern = 'unclassified_2025.06.19.04'  # Matches unclassified_yyyy.mm.dd.hh
    
    print("Fetching data from Elasticsearch...")
    df, original_docs = fetch_elasticsearch_data(index_pattern)
    print(f"Fetched {len(df)} records")
    
    print("\nPreprocessing data...")
    df_processed, transaction_ids = preprocess_unclassified_data(df)
    print("Preprocessing complete")
    
    print("\nClassifying and sending to Elasticsearch...")
    result = classify_and_send_to_elastic(df_processed, transaction_ids, original_docs)
    print("\nClassification Results:")
    print(f"Classified Index: {result['classified_index']}")
    print(f"Total Documents: {result['total_documents']}")
    print(f"Successfully Indexed: {result['successful']}")
    print(f"Failed to Index: {result['failed']}")
