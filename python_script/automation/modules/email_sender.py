import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from typing import Dict, Optional
from .config import Config
import base64

def create_html_content(target_stats: Dict, kibana_url: str, new_rule: Optional[Dict] = None,
                       has_target_dist: bool = False, has_anomaly_weight: bool = False) -> str:
    """
    Create HTML content for the email.
    
    Args:
        target_stats: Dictionary containing attack statistics
        kibana_url: URL to Kibana dashboard
        new_rule: Dictionary containing information about newly added rule (if any)
        has_target_dist: Whether target distribution image is included
        has_anomaly_weight: Whether anomaly weight image is included
        
    Returns:
        str: HTML content for the email
    """
    html = f"""
    <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: #c0392b;">⚠️ Security Alert: Attack Traffic Detected</h2>
            
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0;">
                <h3>Traffic Analysis</h3>
                <p>Total Records: <strong>{target_stats['total_records']}</strong></p>
                <p>Attack Percentage: <strong style="color: #e74c3c;">{target_stats['attack_percentage']}%</strong></p>
                <p>Normal Percentage: <strong style="color: #2ecc71;">{target_stats['normal_percentage']}%</strong></p>
                <p>View in Kibana: <a href="{kibana_url}" style="color: #3498db;">Open Dashboard</a></p>
            </div>
    """
    
    if new_rule:
        html += f"""
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0;">
                <h3>New Rule Added</h3>
                <p>Rule ID: <strong>{new_rule['rule_id']}</strong></p>
                <p>Triggered Count: <strong>{new_rule['count']}</strong></p>
                <p>Severity: <strong>{new_rule['severity']}</strong></p>
                <p>Paranoia Level: <strong>{new_rule['paranoia_level']}</strong></p>
            </div>
        """
    
    if has_target_dist:
        html += """
            <div style="margin: 20px 0;">
                <h3>Traffic Distribution</h3>
                <img src="cid:target_distribution" style="max-width: 100%;">
            </div>
        """
        
    if has_anomaly_weight:
        html += """
            <div style="margin: 20px 0;">
                <h3>Anomaly Score vs Weight Analysis</h3>
                <img src="cid:anomaly_weight" style="max-width: 100%;">
            </div>
        """
    
    html += """
        </body>
    </html>
    """
    
    return html

def send_attack_notification(config: 'Config', recipient_email: str, target_stats: Dict,
                           new_rule: Optional[Dict] = None, target_dist_img: str = None,
                           anomaly_weight_img: str = None) -> None:
    """
    Send an email notification about detected attacks.
    
    Args:
        config: Config object containing SMTP and other settings
        recipient_email: Email address to send the notification to
        target_stats: Dictionary containing attack statistics
        new_rule: Dictionary containing information about newly added rule (if any)
        target_dist_img: Base64 encoded image of target distribution
        anomaly_weight_img: Base64 encoded image of anomaly vs weight comparison
    """
    # Create Kibana URL (assuming default port 5601)
    kibana_base_url = config.es_host.replace(':9200', ':3012')
    kibana_url = f"{kibana_base_url}/app/dashboards#/view/a4d51715-8ed9-43da-94c0-acabd0945594?_g=(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:'2025-06-14T15:48:43.943Z',to:now))"
    # kibana_url = f"{kibana_base_url}/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-24h,to:now))&_a=(columns:!(_source),filters:!(),index:'{config.es_index}')"

    # Create message container
    msg = MIMEMultipart('related')
    msg['Subject'] = '⚠️ Security Alert: Attack Traffic Detected'
    msg['From'] = config.sender_email
    msg['To'] = recipient_email
    
    # Create HTML content
    html_content = create_html_content(
        target_stats,
        kibana_url,
        new_rule,
        bool(target_dist_img),
        bool(anomaly_weight_img)
    )
    
    msg.attach(MIMEText(html_content, 'html'))
    
    # Attach images if available
    if target_dist_img:
        # Decode base64 string and create image
        img_data = base64.b64decode(target_dist_img)
        img = MIMEImage(img_data, _subtype='png')
        img.add_header('Content-ID', '<target_distribution>')
        msg.attach(img)
        
    if anomaly_weight_img:
        # Decode base64 string and create image
        img_data = base64.b64decode(anomaly_weight_img)
        img = MIMEImage(img_data, _subtype='png')
        img.add_header('Content-ID', '<anomaly_weight>')
        msg.attach(img)
    
    # Send email
    with smtplib.SMTP(config.smtp_server, 587) as server:  # Using standard SMTP port
        server.starttls()
        server.login(config.sender_email, config.sender_password)
        server.send_message(msg)
