import pandas as pd
import numpy as np
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, ConnectionTimeout, RequestError, NotFoundError
from elasticsearch.helpers import scan, bulk
import joblib
from modules.data_preprocessor import preprocess_http_data, standardize_column_names
from modules.user_agent_processor import process_user_agent_features
from modules.text_processor import create_tfidf_vectors, preprocess_text

# --- CONFIGURATION ---
ES_HOST = 'http://192.168.0.109:9200'  # Change if needed
ES_TIMEOUT = 30  # Timeout in seconds
MAX_RETRIES = 3

def fetch_elasticsearch_data(index_pattern, size=10000):
    """Fetch all documents from the given index pattern."""
    try:
        # Update client configuration to use request_timeout instead of deprecated timeout
        es = Elasticsearch(
            ES_HOST,
            request_timeout=ES_TIMEOUT,
            max_retries=MAX_RETRIES,
            retry_on_timeout=True
        )
        
        # Check if index exists using the correct API call
        try:
            if not es.indices.exists(index=index_pattern):
                print(f"Warning: Index pattern {index_pattern} not found")
                return None, None
        except Exception as e:
            print(f"Warning: Could not check index existence: {e}")
            # Continue anyway as the scan operation will fail if index doesn't exist
        
        results = []
        original_docs = []
        
        query = {
            "query": {
                "match_all": {}
            }
        }
        
        try:
            for doc in scan(es, index=index_pattern, query=query, size=size, request_timeout=ES_TIMEOUT):
                source = doc.get('_source', {})
                original_docs.append(source)
                
                processed_doc = {
                    'http_method': source.get('http_method', '').upper(),
                    'request_path': source.get('request_path', '/'),
                    'request_body': source.get('request_body', ''),
                    'user_agent': source.get('user_agent', 'Unknown'),
                    'content_length': source.get('content_length', 0),
                    'transaction_id': source.get('transaction_id', '')
                }
                results.append(processed_doc)
        except Exception as e:
            print(f"Error during document scanning: {e}")
            raise
        
        if not results:
            print(f"Warning: No documents found in index {index_pattern}")
            return None, None
            
        return pd.DataFrame(results), original_docs
        
    except ConnectionTimeout as e:
        print(f"Error: Connection timeout while fetching data: {e}")
        raise
    except RequestError as e:
        print(f"Error: Invalid request while fetching data: {e}")
        raise
    except Exception as e:
        print(f"Error: Unexpected error while fetching data: {e}")
        raise

def preprocess_unclassified_data(df):
    """Preprocess data to match the training data format."""
    try:
        if df is None or df.empty:
            raise ValueError("No data to preprocess")
            
        print("Starting preprocessing...")
        print(f"Initial shape: {df.shape}")
        
        # Standardize column names
        df = standardize_column_names(df)
        print("Standardized column names")
        
        # Preprocess HTTP data
        df = preprocess_http_data(df)
        print("Preprocessed HTTP data")
        
        # Process user agent features
        try:
            ua_features = process_user_agent_features(df)
            df = pd.concat([df, ua_features], axis=1)
            df = df.drop(columns=['user_agent'])
            print("Processed user agent features")
        except Exception as e:
            print(f"Warning: Error processing user agent features: {e}")
            # Continue without user agent features if they fail
        
        # Process HTTP method
        try:
            http_method_dummies = pd.get_dummies(df['http_method'], prefix='http_method')
            df = pd.concat([df, http_method_dummies], axis=1)
            df = df.drop(columns=['http_method'])
            print("Processed HTTP method")
        except Exception as e:
            print(f"Error processing HTTP method: {e}")
            raise
        
        # Process request body with TF-IDF
        try:
            print("Processing request bodies...")
            body_texts = df["request_body"].fillna('').astype(str)
            body_texts = body_texts.apply(lambda x: preprocess_text('empty_body') if x.strip() == '' else preprocess_text(x))
            body_vectors, _ = create_tfidf_vectors(
                body_texts, 
                max_features=100,
                verbose=True,
                batch_size=500,
                min_df=1,
                max_df=1.0
            )
            body_feature_names = [f'body_tfidf_{i}' for i in range(body_vectors.shape[1])]
            # Fix for pandas linter error - convert list to Index
            body_features = pd.DataFrame(
                body_vectors, 
                columns=pd.Index(body_feature_names), 
                index=df.index
            )
            df = pd.concat([df, body_features], axis=1)
            df = df.drop(columns=['request_body'])
            print("Processed request bodies")
        except Exception as e:
            print(f"Error processing request bodies: {e}")
            raise
        
        # Process request paths with TF-IDF
        try:
            print("Processing request paths...")
            path_texts = df["request_path"].fillna('/').astype(str)
            path_texts = path_texts.apply(preprocess_text)
            path_vectors, _ = create_tfidf_vectors(
                path_texts, 
                max_features=100,
                verbose=True,
                batch_size=500,
                min_df=1,
                max_df=1.0
            )
            path_feature_names = [f'path_tfidf_{i}' for i in range(path_vectors.shape[1])]
            # Fix for pandas linter error - convert list to Index
            path_features = pd.DataFrame(
                path_vectors, 
                columns=pd.Index(path_feature_names), 
                index=df.index
            )
            df = pd.concat([df, path_features], axis=1)
            df = df.drop(columns=['request_path'])
            print("Processed request paths")
        except Exception as e:
            print(f"Error processing request paths: {e}")
            raise
        
        # Convert boolean columns to int
        try:
            bool_cols = df.select_dtypes(include=['bool']).columns
            for col in bool_cols:
                df[col] = df[col].astype(int)
        except Exception as e:
            print(f"Warning: Error converting boolean columns: {e}")
        
        # Keep track of transaction IDs
        transaction_ids = df['transaction_id'] if 'transaction_id' in df.columns else None
        if 'transaction_id' in df.columns:
            df = df.drop(columns=['transaction_id'])
        
        print(f"Final shape: {df.shape}")
        return df, transaction_ids
        
    except Exception as e:
        print(f"Error during preprocessing: {e}")
        raise

def classify_and_send_to_elastic(df, transaction_ids, original_docs, model_path="random_forest_trained.joblib"):
    """Classify the preprocessed data and send it back to Elasticsearch."""
    try:
        if df is None or df.empty:
            raise ValueError("No data to classify")
            
        # Load the model
        try:
            clf = joblib.load(model_path)
        except Exception as e:
            print(f"Error loading model: {e}")
            raise
        
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
        try:
            predictions = clf.predict(prediction_df)
        except Exception as e:
            print(f"Error making predictions: {e}")
            raise
        
        # Create the classified index name
        time_utc = datetime.now(timezone.utc)
        classified_index = f"classified_{time_utc.strftime('%Y.%m.%d.%H')}"
        
        # Prepare documents for bulk indexing
        actions = []
        for pred, original_doc in zip(predictions, original_docs):
            doc = {
                '_index': classified_index,
                '_source': original_doc
            }
            doc['_source'].update({
                'target': int(pred),
                'classification_timestamp': time_utc.isoformat()
            })
            actions.append(doc)
        
        # Send to Elasticsearch with retry logic
        es = Elasticsearch(
            ES_HOST,
            request_timeout=ES_TIMEOUT,
            max_retries=MAX_RETRIES,
            retry_on_timeout=True
        )
        
        try:
            success, failed = bulk(es, actions, request_timeout=ES_TIMEOUT)
        except Exception as e:
            print(f"Error sending data to Elasticsearch: {e}")
            raise
        
        return {
            'classified_index': classified_index,
            'total_documents': len(predictions),
            'successful': success,
            'failed': failed
        }
        
    except Exception as e:
        print(f"Error during classification and indexing: {e}")
        raise

if __name__ == "__main__":
    try:
        # Get current date-based index
        time_utc = datetime.now(timezone.utc).strftime('%Y.%m.%d.%H')
        index_pattern = f'unclassified_{time_utc}'
        
        print("Fetching data from Elasticsearch...")
        df, original_docs = fetch_elasticsearch_data(index_pattern)
        
        if df is not None and not df.empty:
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
        else:
            print("No data to process")
            
    except Exception as e:
        print(f"Error in main execution: {e}")
        exit(1)
