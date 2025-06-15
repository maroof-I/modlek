import pandas as pd  # For data manipulation
import numpy as np   # For numerical operations
from sklearn.preprocessing import MinMaxScaler  # For norma# 4. Word2Vec embeddings for request_body and request_path
from gensim.models import Word2Vec  # For word embeddings
import re  # For regular expressions
import nltk  # For natural language processing
from nltk.tokenize import word_tokenize  # For text tokenization
from nltk.corpus import stopwords  # For removing common words
import warnings
warnings.filterwarnings('ignore')  # To suppress warnings

# Download required NLTK data
try:
    nltk.download('stopwords', quiet=True)
except:
    print("Could not download stopwords, will skip stopword removal")

# # df_original_ds = pd.read_csv("machine_learning/csic_database.csv", nrows=30)

# # df_csv = df_original_ds.to_csv("machine_learning/sample_http.csv", index=True)

# # ,Unnamed: 0,Method,User-Agent,Pragma,Cache-Control,Accept,Accept-encoding,Accept-charset,
# # language,host,cookie,content-type,connection,lenght,content,classification,URL
# # delete unnamed column, pragma, cache-control, accept, Accept-encoding, Accept-charset, lannguage
# # host, cookie, connectionm, content-type

df_sample = pd.read_csv("machine_learning/sample_http.csv")

df_sample = df_sample.drop(columns=[
    "Unnamed: 0.1", "Pragma", "Cache-Control", "Accept", "Accept-encoding",
    "Accept-charset", "language", "host", "cookie", "content-type", "connection"
])

# Function to extract content length value
def extract_content_length(value):
    if pd.isna(value):
        return 0
    value = str(value)
    if "Content-Length:" in value:
        try:
            return int(value.split("Content-Length:")[1].strip())
        except:
            return 0
    return 0

# Rename remaining columns to match target format
df_sample = df_sample.rename(columns={
    "Method": "http_method",
    "User-Agent": "user_agent",
    "content": "request_body",
    "URL": "request_path",
    "classification": "target",
    "lenght": "content_length"
})

# Process the content length to extract the number
df_sample["content_length"] = df_sample["content_length"].apply(extract_content_length)

df_sample.to_csv("machine_learning/sample_match.csv", index=False)

df_sample_match = pd.read_csv("machine_learning/sample_match.csv")
df_sample_match["user_agent"] = df_sample_match["user_agent"].fillna("Unknown")
df_sample_match["request_body"] = df_sample_match["request_body"].fillna("")
df_sample_match["request_path"] = df_sample_match["request_path"].fillna("/")
df_sample_match["content_length"] = df_sample_match["content_length"].fillna(0)

# drop duplicate rows
df_sample_match = df_sample_match.drop_duplicates()

# 1. Enhanced One-hot encoding for http_method using get_dummies
http_method_dummies = pd.get_dummies(df_sample_match['http_method'], prefix='http_method')
df_sample_match = pd.concat([df_sample_match, http_method_dummies], axis=1)
df_sample_match = df_sample_match.drop(columns=['http_method'])

# 2. Enhanced User-Agent Tokenization and Feature Engineering
def process_user_agent(ua):
    ua = str(ua).lower()
    
    # Extract browser information
    browsers = {
        'chrome': ['chrome', 'chromium'],
        'firefox': ['firefox', 'mozilla'],
        'safari': ['safari'],
        'opera': ['opera'],
        'edge': ['edge', 'edg'],
        'ie': ['msie', 'trident'],
        'mobile': ['mobile', 'android', 'iphone']
    }
    
    # Extract OS information
    os_systems = {
        'windows': ['windows nt'],
        'linux': ['linux', 'x11'],
        'mac': ['macintosh', 'mac os'],
        'android': ['android'],
        'ios': ['iphone', 'ipad', 'ios']
    }
    
    # Initialize features
    features = {
        'browser_type': 'other',
        'os_type': 'other',
        'is_mobile': 0,
        'is_bot': 0,
        'browser_version': 0.0,
        'ua_length': len(ua),
        'ua_word_count': len(ua.split())
    }
    
    # Detect browser
    for browser, patterns in browsers.items():
        if any(pattern in ua for pattern in patterns):
            features['browser_type'] = browser
            break
    
    # Detect OS
    for os_name, patterns in os_systems.items():
        if any(pattern in ua for pattern in patterns):
            features['os_type'] = os_name
            break
    
    # Detect if mobile
    features['is_mobile'] = 1 if any(x in ua for x in ['mobile', 'android', 'iphone', 'ipad']) else 0
    
    # Detect if bot
    features['is_bot'] = 1 if any(x in ua for x in ['bot', 'crawler', 'spider']) else 0
    
    # Extract version numbers
    versions = re.findall(r'[\d]+\.[\d]+', ua)
    features['browser_version'] = float(versions[0]) if versions else 0.0
    
    return pd.Series(features)

ua_features = df_sample_match["user_agent"].apply(process_user_agent)

# One-hot encode browser_type and os_type
browser_dummies = pd.get_dummies(ua_features['browser_type'], prefix='browser')
os_dummies = pd.get_dummies(ua_features['os_type'], prefix='os')

# Drop the original categorical columns and keep only numeric ones
ua_features = ua_features.drop(columns=['browser_type', 'os_type'])

# Combine all user agent features
ua_features = pd.concat([ua_features, browser_dummies, os_dummies], axis=1)

df_sample_match = pd.concat([df_sample_match, ua_features], axis=1)
df_sample_match = df_sample_match.drop(columns=["user_agent"])

# 3. Enhanced normalization for content_length using MinMaxScaler to scale between 0 and 1
minmax_scaler = MinMaxScaler(feature_range=(0, 1))
df_sample_match["content_length_normalized"] = minmax_scaler.fit_transform(
    df_sample_match[["content_length"]].replace(0, np.nan).fillna(df_sample_match["content_length"].median())
)

# 4. Enhanced Word2Vec embeddings for request_body and request_path
def preprocess_text(text):
    """Preprocess text for Word2Vec."""
    # Convert to string and lowercase
    text = str(text).lower()
    
    # Remove URLs
    text = re.sub(r'http\S+|www.\S+', '', text)
    
    # Remove special characters but keep important ones for security analysis
    text = re.sub(r'[^\w\s\'"{}()/\\=&?;]', ' ', text)
    
    # Simple tokenization by splitting on whitespace and keeping important characters
    tokens = []
    for word in text.split():
        # Split on special characters while keeping them as tokens
        for token in re.findall(r'[\w]+|[{}\(\)\/\\=&?;]', word):
            if token.strip():  # Only keep non-empty tokens
                tokens.append(token)
    
    # Remove common English stopwords
    try:
        stop_words = set(stopwords.words('english'))
        tokens = [token for token in tokens if token not in stop_words]
    except:
        pass
    
    return tokens

def get_document_vector(tokens, model):
    """Convert tokens to document vector."""
    vectors = []
    for token in tokens:
        if token in model.wv:
            vectors.append(model.wv[token])
    
    if vectors:
        doc_vector = np.mean(vectors, axis=0)
        doc_vector = doc_vector / np.linalg.norm(doc_vector)
        return doc_vector
    return np.zeros(model.vector_size)

# Prepare texts for Word2Vec
print("Preprocessing request body and path...")
request_body_tokens = df_sample_match["request_body"].apply(preprocess_text).tolist()
request_path_tokens = df_sample_match["request_path"].apply(preprocess_text).tolist()

# Debug print
print(f"Number of request body documents: {len(request_body_tokens)}")
print(f"Sample of first request body tokens: {request_body_tokens[0] if request_body_tokens else 'Empty'}")
print(f"Number of request path documents: {len(request_path_tokens)}")
print(f"Sample of first request path tokens: {request_path_tokens[0] if request_path_tokens else 'Empty'}")

# Filter out empty lists and ensure we have valid training data
request_body_tokens = [tokens for tokens in request_body_tokens if tokens]
request_path_tokens = [tokens for tokens in request_path_tokens if tokens]

print(f"Number of non-empty request body documents: {len(request_body_tokens)}")
print(f"Number of non-empty request path documents: {len(request_path_tokens)}")

# Train Word2Vec models if we have data
if request_body_tokens:
    print("Training request body Word2Vec model...")
    body_w2v = Word2Vec(sentences=request_body_tokens, vector_size=100, window=5, min_count=1, workers=4)
else:
    print("No valid request body data for Word2Vec")
    body_w2v = None

if request_path_tokens:
    print("Training request path Word2Vec model...")
    path_w2v = Word2Vec(sentences=request_path_tokens, vector_size=100, window=5, min_count=1, workers=4)
else:
    print("No valid request path data for Word2Vec")
    path_w2v = None

# Create embeddings
print("Creating embeddings...")
if body_w2v:
    df_sample_match["request_body_embedding"] = df_sample_match["request_body"].apply(
        lambda x: get_document_vector(preprocess_text(x), body_w2v)
    )
else:
    df_sample_match["request_body_embedding"] = df_sample_match["request_body"].apply(
        lambda x: np.zeros(100)
    )

if path_w2v:
    df_sample_match["request_path_embedding"] = df_sample_match["request_path"].apply(
        lambda x: get_document_vector(preprocess_text(x), path_w2v)
    )
else:
    df_sample_match["request_path_embedding"] = df_sample_match["request_path"].apply(
        lambda x: np.zeros(100)
    )

# Remove original text columns
df_sample_match = df_sample_match.drop(columns=["request_body", "request_path"])

# Save the processed dataset
df_sample_match.to_csv("machine_learning/sample_match_processed.csv", index=False)
print("Processing completed successfully!")
