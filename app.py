from flask import Flask, request, jsonify, render_template, send_file
import os
import tempfile
import uuid
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress
import threading
import time

app = Flask(__name__)

# Store generated certificates temporarily (in production, use a database)
cert_storage = {}

@app.route('/')
def index():
    return render_template('index.html')

def is_valid_ip(ip_string):
    """Check if a string is a valid IP address"""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def cleanup_old_certificates():
    """Remove certificates older than 1 hour"""
    current_time = time.time()
    expired_keys = []
    
    for cert_id, cert_data in cert_storage.items():
        if current_time - cert_data['created_at'] > 3600:  # 1 hour
            expired_keys.append(cert_id)
    
    for key in expired_keys:
        del cert_storage[key]

def start_cleanup_thread():
    """Start background thread for certificate cleanup"""
    def cleanup_loop():
        while True:
            cleanup_old_certificates()
            time.sleep(3600)  # Run every hour
    
    cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
    cleanup_thread.start()

@app.route('/generate', methods=['POST'])
def generate_certificate():
    try:
        data = request.json
        
        # Extract form data
        common_name = data.get('commonName', '').strip()
        country = data.get('country', '').strip().upper()
        state = data.get('state', '').strip()
        city = data.get('city', '').strip()
        organization = data.get('organization', '').strip()
        valid_days = int(data.get('validDays', 365))
        key_size = int(data.get('keySize', 2048))
        
        # Validate required fields
        if not all([common_name, country, state, city, organization]):
            return jsonify({'error': 'All fields are required'}), 400
        
        if len(country) != 2:
            return jsonify({'error': 'Country must be a 2-letter code (e.g., US)'}), 400
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        
        # Create certificate subject
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, city),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # Create certificate
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(private_key.public_key())
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        
        # Set validity period
        now = datetime.utcnow()
        cert_builder = cert_builder.not_valid_before(now)
        cert_builder = cert_builder.not_valid_after(now + timedelta(days=valid_days))
        
        # Add Subject Alternative Name (SAN)
        san_list = []
        if is_valid_ip(common_name):
            san_list.append(x509.IPAddress(ipaddress.ip_address(common_name)))
        else:
            san_list.append(x509.DNSName(common_name))
        
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
        
        # Add basic constraints
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        
        # Add key usage
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        
        # Add extended key usage
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True,
        )
        
        # Sign the certificate
        certificate = cert_builder.sign(private_key, hashes.SHA256())
        
        # Serialize certificate and private key
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Generate unique ID for this certificate
        cert_id = str(uuid.uuid4())
        
        # Store certificate data
        cert_storage[cert_id] = {
            'certificate': cert_pem.decode('utf-8'),
            'private_key': key_pem.decode('utf-8'),
            'common_name': common_name,
            'valid_from': now.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'valid_until': (now + timedelta(days=valid_days)).strftime('%Y-%m-%d %H:%M:%S UTC'),
            'key_size': key_size,
            'serial_number': str(certificate.serial_number),
            'created_at': time.time()
        }
        
        return jsonify({
            'success': True,
            'cert_id': cert_id,
            'common_name': common_name,
            'valid_from': cert_storage[cert_id]['valid_from'],
            'valid_until': cert_storage[cert_id]['valid_until'],
            'key_size': key_size,
            'serial_number': cert_storage[cert_id]['serial_number']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/cert/<cert_id>')
def download_certificate(cert_id):
    if cert_id not in cert_storage:
        return jsonify({'error': 'Certificate not found'}), 404
    
    cert_data = cert_storage[cert_id]
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
        f.write(cert_data['certificate'])
        temp_path = f.name
    
    def remove_file(response):
        try:
            os.unlink(temp_path)
        except Exception:
            pass
        return response
    
    return send_file(
        temp_path,
        as_attachment=True,
        download_name=f"{cert_data['common_name']}.crt",
        mimetype='application/x-x509-ca-cert'
    )

@app.route('/download/key/<cert_id>')
def download_private_key(cert_id):
    if cert_id not in cert_storage:
        return jsonify({'error': 'Private key not found'}), 404
    
    cert_data = cert_storage[cert_id]
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as f:
        f.write(cert_data['private_key'])
        temp_path = f.name
    
    def remove_file(response):
        try:
            os.unlink(temp_path)
        except Exception:
            pass
        return response
    
    return send_file(
        temp_path,
        as_attachment=True,
        download_name=f"{cert_data['common_name']}.key",
        mimetype='application/x-pem-file'
    )

if __name__ == '__main__':
    # Start the cleanup thread
    start_cleanup_thread()
    
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)
