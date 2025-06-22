import re
import pandas as pd

def process_user_agent(ua):
    """Process user agent string to extract features."""
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

def process_user_agent_features(df, user_agent_column='user_agent'):
    """Process user agent column in a dataframe and return features."""
    ua_features = df[user_agent_column].apply(process_user_agent)
    
    # One-hot encode browser_type and os_type
    browser_dummies = pd.get_dummies(ua_features['browser_type'], prefix='browser')
    os_dummies = pd.get_dummies(ua_features['os_type'], prefix='os')
    
    # Drop the original categorical columns and keep only numeric ones
    ua_features = ua_features.drop(columns=['browser_type', 'os_type'])
    
    # Combine all user agent features
    return pd.concat([ua_features, browser_dummies, os_dummies], axis=1)
