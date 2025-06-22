import matplotlib.pyplot as plt
import io
import base64

def create_target_distribution_plot(normal_pct, attack_pct):
    """
    Create a pie chart showing normal vs attack traffic distribution.
    
    Args:
        normal_pct (float): Percentage of normal traffic
        attack_pct (float): Percentage of attack traffic
        
    Returns:
        str: Base64 encoded PNG image
    """
    plt.figure(figsize=(8, 6))
    plt.pie([normal_pct, attack_pct], 
            labels=['Normal', 'Malicious'], 
            autopct='%1.1f%%',
            colors=['#2ecc71', '#e74c3c'])
    plt.title('Traffic Distribution')
    
    # Save plot to bytes buffer
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    plt.close()
    buffer.seek(0)
    return base64.b64encode(buffer.read()).decode()

def create_anomaly_weight_plot(anomaly_scores, weights):
    """
    Create a bar chart comparing average anomaly scores and weights.
    
    Args:
        anomaly_scores (float): Average anomaly scores
        weights (float): Average weights
        
    Returns:
        str: Base64 encoded PNG image
    """
    plt.figure(figsize=(10, 6))
    
    x = ['Anomaly Score', 'Weight']
    y = [anomaly_scores, weights]
    
    plt.bar(x, y, color=['#3498db', '#9b59b6'])
    plt.title('Average Anomaly Score vs Weight')
    plt.ylabel('Value')
    
    # Add value labels on top of bars
    for i, v in enumerate(y):
        plt.text(i, v, f'{v:.2f}', ha='center', va='bottom')
    
    # Save plot to bytes buffer
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    plt.close()
    buffer.seek(0)
    return base64.b64encode(buffer.read()).decode()
