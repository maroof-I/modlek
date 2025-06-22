import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler

def extract_content_length(value):
    """Extract content length value from string."""
    if pd.isna(value):
        return 0
    value = str(value)
    if "Content-Length:" in value:
        try:
            return int(value.split("Content-Length:")[1].strip())
        except:
            return 0
    return 0

def preprocess_http_data(df):
    """Preprocess HTTP data for analysis."""
    # Create a copy of the dataframe to avoid modifying the original
    df = df.copy()
    
    # Fill missing values using loc
    df.loc[:, "user_agent"] = df["user_agent"].fillna("Unknown")
    df.loc[:, "request_body"] = df["request_body"].fillna("")
    df.loc[:, "request_path"] = df["request_path"].fillna("/")
    df.loc[:, "content_length"] = df["content_length"].fillna(0)
    
    # Process content length using loc
    df.loc[:, "content_length"] = df["content_length"].apply(extract_content_length)
    
    # Normalize content length
    minmax_scaler = MinMaxScaler(feature_range=(0, 1))
    df.loc[:, "content_length_normalized"] = minmax_scaler.fit_transform(
        df[["content_length"]].replace(0, np.nan).fillna(df["content_length"].median())
    )
    
    return df

def sample_traffic_data(df, normal_samples=6000, malicious_samples=1500, random_state=42):
    """Sample specific numbers of normal and malicious traffic.
    
    Args:
        df: Input DataFrame
        normal_samples: Number of normal traffic samples to select (default: 750)
        malicious_samples: Number of malicious traffic samples to select (default: 250)
        random_state: Random seed for reproducibility (default: 42)
    
    Note: If all samples are requested (normal_samples=None or malicious_samples=None),
          the function will return all available samples for that category.
    """
    # If None is provided for samples, use all available samples
    use_all_normal = normal_samples is None
    use_all_malicious = malicious_samples is None
    # Create a copy of the dataframe
    df = df.copy()
    
    # Print initial counts
    print("\nInitial classification counts:")
    print(df['classification'].value_counts())
    
    # Separate normal and malicious traffic
    normal_traffic = df[df['classification'] == 0].copy()
    malicious_traffic = df[df['classification'] == 1].copy()
    
    print(f"\nNormal traffic count: {len(normal_traffic)}")
    print(f"Malicious traffic count: {len(malicious_traffic)}")
    
    # Check if we have enough samples
    if len(normal_traffic) < normal_samples:
        print(f"\nWarning: Not enough normal traffic samples. Have {len(normal_traffic)}, need {normal_samples}")
        normal_samples = len(normal_traffic)
    
    if len(malicious_traffic) < malicious_samples:
        print(f"\nWarning: Not enough malicious traffic samples. Have {len(malicious_traffic)}, need {malicious_samples}")
        malicious_samples = len(malicious_traffic)
    
    # Sample the specified number of records
    if use_all_normal:
        sampled_normal = normal_traffic
        print(f"Using all {len(normal_traffic)} normal traffic samples")
    else:
        sampled_normal = normal_traffic.sample(n=normal_samples, random_state=random_state)
        print(f"Sampled {len(sampled_normal)} out of {len(normal_traffic)} normal traffic samples")
    
    if use_all_malicious:
        sampled_malicious = malicious_traffic
        print(f"Using all {len(malicious_traffic)} malicious traffic samples")
    else:
        sampled_malicious = malicious_traffic.sample(n=malicious_samples, random_state=random_state)
        print(f"Sampled {len(sampled_malicious)} out of {len(malicious_traffic)} malicious traffic samples")
    
    # Combine the samples
    combined_df = pd.concat([sampled_normal, sampled_malicious])
    
    # Shuffle the combined dataset
    return combined_df.sample(frac=1, random_state=random_state).reset_index(drop=True)

def standardize_column_names(df):
    """Standardize column names to match target format."""
    return df.rename(columns={
        "Method": "http_method",
        "User-Agent": "user_agent",
        "content": "request_body",
        "URL": "request_path",
        "classification": "target",
        "lenght": "content_length"
    })
