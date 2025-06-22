import re
import nltk
from nltk.corpus import stopwords
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

# Download required NLTK data
try:
    nltk.download('stopwords', quiet=True)
except:
    print("Could not download stopwords, will skip stopword removal")

# Compile regex patterns once for better performance
URL_PATTERN = re.compile(r'https?://[^/]+')
URL_SPLIT_PATTERN = re.compile(r'([/?=&;])')
SPACE_PATTERN = re.compile(r'\s+')

# Compile security patterns once
SECURITY_PATTERNS = [
    # Most common SQL injection patterns
    re.compile(r'(?:union\s+(?:all\s+)?select|select\s+(?:\w+|\*)\s+from)', re.IGNORECASE),
    re.compile(r'(?:drop\s+(?:table|database)|delete\s+from)', re.IGNORECASE),
    
    # Most common LFI patterns
    re.compile(r'(?:\.\.\/|\.\/|~\/)', re.IGNORECASE),
    re.compile(r'(?:/etc/(?:passwd|shadow))', re.IGNORECASE),
    re.compile(r'(?:php://(?:filter|input)|file://)', re.IGNORECASE),
    
    # Most common XSS patterns
    re.compile(r'(?:<script>|<\/script>|javascript:)', re.IGNORECASE),
    
    # Most common command injection
    re.compile(r'(?:;\s*\w+\s*;|`.*`|\|\s*\w+)', re.IGNORECASE),
]

def preprocess_text(text, verbose=False):
    """Optimized text preprocessing."""
    if verbose:
        print(f"\nProcessing text of length: {len(text)}")
    
    # Convert to string and lowercase
    text = str(text).lower()
    
    # Handle empty or invalid input
    if text.strip() == '' or text.strip() == 'nan':
        return ''
    
    # Remove URLs but keep the path
    text = URL_PATTERN.sub('', text)
    
    # Normalize spaces and special characters
    text = SPACE_PATTERN.sub(' ', text)
    text = text.replace('\\', '/').replace('//', '/')
    
    # Split URL components while preserving structure
    text = URL_SPLIT_PATTERN.sub(r' \1 ', text)
    
    # Process security patterns
    for pattern in SECURITY_PATTERNS:
        text = pattern.sub(lambda m: f' SECPAT_{m.group()}_SECPAT ', text)
    
    # Remove common English stopwords but keep security-relevant terms
    try:
        stop_words = set(stopwords.words('english')) - {
            'select', 'where', 'or', 'and', 'union', 'from',
            'delete', 'drop', 'insert', 'into', 'exec'
        }
        words = text.split()
        words = [word for word in words if word not in stop_words]
        text = ' '.join(words)
    except:
        pass
    
    return text

def create_tfidf_vectors(texts, max_features=100, verbose=False, batch_size=1000, min_df=2, max_df=0.95):
    """Memory-efficient TF-IDF vectorization with batching."""
    if verbose:
        print(f"Processing {len(texts)} texts in batches of {batch_size}")
    
    vectorizer = TfidfVectorizer(
        max_features=max_features,
        ngram_range=(1, 2),      # Reduced from (1,3) to (1,2) for performance
        analyzer='char',         
        strip_accents='unicode',
        lowercase=True,
        dtype=np.float32,       # Use float32 instead of float64 to save memory
        max_df=max_df,          # Remove very common terms
        min_df=min_df,          # Remove very rare terms
        use_idf=True,
        norm='l2',
        smooth_idf=True
    )
    
    try:
        # Convert texts to list if it's a Series
        if hasattr(texts, 'tolist'):
            texts = texts.tolist()
        
        # Process texts in batches
        processed_texts = []
        total = len(texts)
        
        for i in range(0, total, batch_size):
            if verbose and i % (batch_size * 10) == 0:
                print(f"Processing batch {i//batch_size + 1}/{(total-1)//batch_size + 1}")
            
            batch = texts[i:i + batch_size]
            processed_batch = [preprocess_text(text, verbose=False) for text in batch]
            processed_texts.extend(processed_batch)
        
        if verbose:
            print("Fitting TF-IDF vectorizer...")
        
        vectors = vectorizer.fit_transform(processed_texts)
        
        if verbose:
            print(f"Created {vectors.shape[1]} features from {len(texts)} texts")
            print(f"Memory usage: {vectors.data.nbytes / 1024 / 1024:.2f} MB")
        
        return vectors.toarray(), vectorizer
        
    except Exception as e:
        print(f"Error in TF-IDF vectorization: {e}")
        return np.zeros((len(texts), max_features)), None
