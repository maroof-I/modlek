import pandas as pd
import numpy as np
from modules.text_processor import create_tfidf_vectors, preprocess_text
from modules.user_agent_processor import process_user_agent_features
from modules.data_preprocessor import (
    preprocess_http_data, 
    sample_traffic_data,
    standardize_column_names
)

# what has been done:
# 1. drop unnecessary columns
# 2. standardize column names
# 3. one hot encode http method
# 4. normalize content length
# 5. feature engineering and selection using user agent
# 6. create tf-idf vectors for request body and path


def process_dataset(input_file, output_file, normal_samples=10000, malicious_samples=2500):
    """Process HTTP dataset with all preprocessing steps."""
    print("\n" + "="*50)
    print("PROCESSING PIPELINE START")
    print("="*50)
    print("\nStep 1: Loading and sampling data...")
    
    # Load data in chunks to save memory
    chunk_size = 5000
    chunks = []
    for chunk in pd.read_csv(input_file, chunksize=chunk_size):
        chunks.append(chunk)
    df_original = pd.concat(chunks)
    print(f"\nLoaded original dataset - Total samples: {len(df_original)}")
    del chunks  # Free up memory
    
    print("\nStep 2: Sampling data...")
    df_sample = sample_traffic_data(
        df_original, 
        normal_samples=normal_samples, 
        malicious_samples=malicious_samples
    )
    print(f"\nAfter sampling - Total samples: {len(df_sample)}")
    del df_original  # Free up memory
    
    print("\nStep 3: Standardizing column names...")
    df_sample = standardize_column_names(df_sample)
    print(f"After standardization - Total samples: {len(df_sample)}")
    
    print("\nStep 4: Dropping unnecessary columns...")
    initial_cols = df_sample.columns.tolist()
    df_sample = df_sample.drop(columns=[
        "Unnamed: 0.1", "Pragma", "Cache-Control", "Accept", "Accept-encoding",
        "Accept-charset", "language", "host", "cookie", "content-type", "connection"
    ], errors='ignore')
    dropped_cols = set(initial_cols) - set(df_sample.columns.tolist())
    print(f"Dropped columns: {dropped_cols}")
    print(f"After dropping columns - Total samples: {len(df_sample)}")
    
    print("\nStep 5: Preprocessing HTTP data...")
    df_sample = preprocess_http_data(df_sample)
    print(f"After HTTP preprocessing - Total samples: {len(df_sample)}")
    
    print("\nStep 6: Processing user agent features...")
    ua_features = process_user_agent_features(df_sample)
    df_sample = pd.concat([df_sample, ua_features], axis=1)
    df_sample = df_sample.drop(columns=["user_agent"])
    print(f"After user agent processing - Total samples: {len(df_sample)}")
    
    print("\nStep 7: Processing HTTP method...")
    http_method_dummies = pd.get_dummies(df_sample['http_method'], prefix='http_method')
    df_sample = pd.concat([df_sample, http_method_dummies], axis=1)
    df_sample = df_sample.drop(columns=['http_method'])
    print(f"After HTTP method processing - Total samples: {len(df_sample)}")
    
    # Process text data
    print("\nProcessing request body and path...")
    
    # Process request bodies
    print("\nProcessing request bodies:")
    sample_bodies = df_sample["request_body"].head(3).tolist()
    print(f"\nSample request bodies:")
    for body in sample_bodies:
        print(f"- {str(body)[:100]}...")
    
    # Process request bodies with TF-IDF (with progress monitoring)
    print("\nCreating TF-IDF vectors for request bodies...")
    body_texts = df_sample["request_body"].fillna('')
    body_vectors, body_vectorizer = create_tfidf_vectors(
        body_texts, 
        max_features=100,
        verbose=True,
        batch_size=500  # Process in smaller batches
    )
    
    # Convert TF-IDF matrix to DataFrame columns
    body_feature_names = [f'body_tfidf_{i}' for i in range(body_vectors.shape[1])]
    body_features = pd.DataFrame(
        body_vectors,
        columns=body_feature_names,
        index=df_sample.index
    )
    del body_vectors  # Free up memory
    
    # Process request paths
    print("\nProcessing request paths:")
    sample_paths = df_sample["request_path"].head(3).tolist()
    print(f"\nSample request paths:")
    for path in sample_paths:
        print(f"- {str(path)[:100]}")
    
    # Process request paths with TF-IDF
    print("\nCreating TF-IDF vectors for request paths...")
    path_texts = df_sample["request_path"].fillna('')
    path_vectors, path_vectorizer = create_tfidf_vectors(
        path_texts, 
        max_features=100,
        verbose=True,
        batch_size=500  # Process in smaller batches
    )
    
    # Convert TF-IDF matrix to DataFrame columns
    path_feature_names = [f'path_tfidf_{i}' for i in range(path_vectors.shape[1])]
    path_features = pd.DataFrame(
        path_vectors,
        columns=path_feature_names,
        index=df_sample.index
    )
    del path_vectors  # Free up memory
    
    # Combine all features
    print("\nCombining features...")
    df_sample = pd.concat([df_sample, body_features, path_features], axis=1)
    del body_features, path_features  # Free up memory
    
    # Remove original text columns
    df_sample = df_sample.drop(columns=["request_body", "request_path"])
    
    # Save the processed dataset
    df_sample.to_csv(output_file, index=False)
    
    # Print final statistics
    print("\nFinal Dataset Statistics:")
    print("-" * 25)
    total_samples = len(df_sample)
    normal_samples = len(df_sample[df_sample['target'] == 0])
    malicious_samples = len(df_sample[df_sample['target'] == 1])
    
    print(f"Total samples: {total_samples}")
    print(f"Normal samples (target=0): {normal_samples} ({normal_samples/total_samples*100:.2f}%)")
    print(f"Malicious samples (target=1): {malicious_samples} ({malicious_samples/total_samples*100:.2f}%)")
    print(f"\nTF-IDF Features:")
    print(f"Bodies: {len(body_feature_names)} features")
    if body_vectorizer:
        print(f"Top body features: {', '.join(body_vectorizer.get_feature_names_out()[:5])}")
    print(f"Paths: {len(path_feature_names)} features")
    if path_vectorizer:
        print(f"Top path features: {', '.join(path_vectorizer.get_feature_names_out()[:5])}")
    print("-" * 25)
    print("Processing completed successfully!")
    
    return df_sample

if __name__ == "__main__":
    # Example usage
    input_file = "machine_learning/csic_database.csv"
    output_file = "machine_learning/large_sample.csv"
    
    process_dataset(input_file, output_file)
