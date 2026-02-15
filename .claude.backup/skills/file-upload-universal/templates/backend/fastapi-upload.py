"""
File Upload Universal - FastAPI Implementation

Multi-storage file upload system with comprehensive security validation.

Storage Providers:
- AWS S3 (primary - general files, documents, videos)
- Cloudinary (images - optimization, responsive images, CDN)
- Local Disk (development only - NOT for production)

Security Features:
- File type validation (MIME + magic bytes)
- File size limits (prevent DoS)
- Filename sanitization (prevent path traversal)
- Malware scanning (ClamAV)
- XSS prevention (SVG sanitization)
- Encryption at rest (S3 SSE-AES256)

OWASP Compliance:
- A01:2021 Broken Access Control (path traversal prevention)
- A03:2021 Injection (no file execution, magic bytes validation)
- A04:2021 Insecure Design (multi-layer validation)
- A05:2021 Security Misconfiguration (private buckets, HTTPS only)
- A08:2021 Software/Data Integrity (file integrity checks, malware scanning)

Installation:
  pip install fastapi uvicorn boto3 cloudinary python-magic pyclamd pillow

Environment Variables:
  # AWS S3 (primary - documents, files)
  AWS_ACCESS_KEY_ID=your_aws_access_key_id
  AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
  AWS_REGION=us-east-1
  S3_BUCKET_NAME=my-app-uploads

  # Cloudinary (images - optimization)
  CLOUDINARY_CLOUD_NAME=your_cloud_name
  CLOUDINARY_API_KEY=your_api_key
  CLOUDINARY_API_SECRET=your_api_secret

  # File upload configuration
  MAX_FILE_SIZE_MB=10
  ALLOWED_EXTENSIONS=.jpg,.jpeg,.png,.gif,.pdf,.docx
  ENABLE_MALWARE_SCAN=true

  # Storage routing
  DEFAULT_STORAGE_PROVIDER=s3  # or 'cloudinary', 'local'

Usage:
  from fastapi import FastAPI, UploadFile, File
  from upload_service import FileUploadService

  app = FastAPI()
  upload_service = FileUploadService()

  @app.post("/api/upload")
  async def upload_file(file: UploadFile = File(...)):
      result = await upload_service.upload(file)
      return result
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from enum import Enum
import os
import uuid
import magic
import mimetypes
import hashlib
import tempfile
import shutil
from pathlib import Path
import logging
from datetime import datetime
import re

# AWS S3
import boto3
from botocore.exceptions import ClientError

# Cloudinary
import cloudinary
import cloudinary.uploader
import cloudinary.api

# Image processing
from PIL import Image

# Malware scanning
try:
    import pyclamd
    CLAMAV_AVAILABLE = True
except ImportError:
    CLAMAV_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# ENUMS AND MODELS
# ============================================================================

class StorageProvider(str, Enum):
    """Supported storage providers"""
    S3 = "s3"
    CLOUDINARY = "cloudinary"
    LOCAL = "local"


class FileType(str, Enum):
    """File type categories"""
    IMAGE = "image"
    DOCUMENT = "document"
    VIDEO = "video"
    AUDIO = "audio"
    ARCHIVE = "archive"


class UploadResponse(BaseModel):
    """Upload response"""
    success: bool
    url: str
    filename: str
    size: int
    content_type: str
    provider: StorageProvider
    file_id: str
    metadata: Optional[Dict[str, Any]] = None


# ============================================================================
# SECURITY CONFIGURATION
# ============================================================================

# File type whitelist (MIME types)
ALLOWED_MIME_TYPES = {
    'image': [
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp',
        'image/svg+xml',
        'image/bmp',
        'image/tiff'
    ],
    'document': [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',  # .docx
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',  # .xlsx
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',  # .pptx
        'text/plain',
        'text/csv',
        'application/rtf'
    ],
    'video': [
        'video/mp4',
        'video/quicktime',  # .mov
        'video/x-msvideo',  # .avi
        'video/x-ms-wmv',
        'video/webm'
    ],
    'audio': [
        'audio/mpeg',  # .mp3
        'audio/wav',
        'audio/ogg',
        'audio/aac'
    ],
    'archive': [
        'application/zip',
        'application/x-rar-compressed',
        'application/x-7z-compressed',
        'application/gzip',
        'application/x-tar'
    ]
}

# File size limits (bytes)
MAX_FILE_SIZE = {
    'image': 10 * 1024 * 1024,      # 10MB
    'document': 25 * 1024 * 1024,   # 25MB
    'video': 500 * 1024 * 1024,     # 500MB
    'audio': 50 * 1024 * 1024,      # 50MB
    'archive': 100 * 1024 * 1024,   # 100MB
    'default': 10 * 1024 * 1024     # 10MB
}

# Extension whitelist
ALLOWED_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.bmp', '.tiff',  # Images
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv', '.rtf',  # Documents
    '.mp4', '.mov', '.avi', '.wmv', '.webm',  # Videos
    '.mp3', '.wav', '.ogg', '.aac',  # Audio
    '.zip', '.rar', '.7z', '.gz', '.tar'  # Archives
}

# Dangerous file extensions (NEVER allow)
DANGEROUS_EXTENSIONS = {
    '.exe', '.dll', '.bat', '.cmd', '.sh', '.bash',  # Executables
    '.php', '.jsp', '.asp', '.aspx', '.cgi',  # Server scripts
    '.js', '.vbs', '.ps1', '.jar',  # Scripts
    '.msi', '.app', '.deb', '.rpm'  # Installers
}


# ============================================================================
# SECURITY HELPERS
# ============================================================================

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal

    Security: Prevents attacks like ../../etc/passwd

    Returns UUID-based filename with original extension

    Example:
        Input: "../../etc/passwd"
        Output: "abc123-uuid.txt"
    """
    # Get extension
    ext = Path(filename).suffix.lower()

    # Validate extension
    if ext in DANGEROUS_EXTENSIONS:
        raise ValueError(f"Dangerous file extension: {ext}")

    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"File extension not allowed: {ext}")

    # Generate safe filename (UUID + extension)
    safe_filename = f"{uuid.uuid4()}{ext}"

    return safe_filename


def validate_file_type(file_bytes: bytes, declared_mime: str) -> str:
    """
    Validate file type using magic bytes

    Security: Prevents MIME type spoofing
    - Declared MIME: What client claims (can be faked)
    - Actual MIME: From file content (cannot be faked)

    Attack Example:
        Upload: shell.php with Content-Type: image/jpeg
        Without magic bytes: Accepted (PHP executed!)
        With magic bytes: Rejected (not a real JPEG)

    Returns:
        actual_mime_type: str
    """
    # Detect actual MIME type from file content
    try:
        actual_mime = magic.from_buffer(file_bytes, mime=True)
    except Exception as e:
        raise ValueError(f"Could not detect file type: {e}")

    # Get all allowed MIME types
    all_allowed = []
    for mime_list in ALLOWED_MIME_TYPES.values():
        all_allowed.extend(mime_list)

    # Check if actual MIME is allowed
    if actual_mime not in all_allowed:
        raise ValueError(f"File type not allowed: {actual_mime}")

    # Check MIME mismatch (spoofing attempt)
    if declared_mime != actual_mime:
        logger.warning(f"MIME mismatch: declared={declared_mime}, actual={actual_mime}")
        # Allow some common mismatches (e.g., image/jpg vs image/jpeg)
        if not is_acceptable_mime_mismatch(declared_mime, actual_mime):
            raise ValueError(f"MIME type mismatch (possible spoofing): {declared_mime} != {actual_mime}")

    return actual_mime


def is_acceptable_mime_mismatch(declared: str, actual: str) -> bool:
    """Check if MIME mismatch is acceptable (common variations)"""
    acceptable_mismatches = [
        ('image/jpg', 'image/jpeg'),
        ('image/jpeg', 'image/jpg'),
        ('text/plain', 'application/octet-stream'),
    ]

    return (declared, actual) in acceptable_mismatches or (actual, declared) in acceptable_mismatches


def validate_file_size(file_size: int, file_type: str) -> bool:
    """
    Validate file size doesn't exceed limits

    Security: Prevents DoS attacks via massive file uploads
    """
    max_size = MAX_FILE_SIZE.get(file_type, MAX_FILE_SIZE['default'])

    if file_size > max_size:
        max_size_mb = max_size / (1024 * 1024)
        raise ValueError(f"File size {file_size} exceeds limit {max_size_mb}MB")

    if file_size == 0:
        raise ValueError("File is empty (0 bytes)")

    return True


def get_file_type_category(mime_type: str) -> str:
    """Get file type category from MIME type"""
    for category, mime_list in ALLOWED_MIME_TYPES.items():
        if mime_type in mime_list:
            return category
    return 'default'


def scan_for_malware(file_path: str) -> bool:
    """
    Scan file for malware using ClamAV

    Security: Prevents virus/malware uploads

    Setup:
        sudo apt-get install clamav clamav-daemon
        sudo systemctl start clamav-daemon
        pip install pyclamd

    Returns:
        True if clean, raises ValueError if malware detected
    """
    if not CLAMAV_AVAILABLE:
        logger.warning("ClamAV not available, skipping malware scan")
        return True

    try:
        # Connect to ClamAV daemon
        cd = pyclamd.ClamdUnixSocket()

        # Check if ClamAV is running
        if not cd.ping():
            raise ConnectionError("ClamAV daemon not responding")

        # Scan file
        result = cd.scan_file(file_path)

        if result is None:
            # Clean file
            logger.info(f"Malware scan: CLEAN - {file_path}")
            return True
        else:
            # Malware detected
            virus_name = result[file_path][1]
            logger.error(f"Malware detected: {virus_name} in {file_path}")
            raise ValueError(f"Malware detected: {virus_name}")

    except ConnectionError as e:
        # ClamAV not running - fail securely (reject upload)
        logger.error(f"ClamAV connection failed: {e}")
        raise ValueError("Malware scanning unavailable. Upload rejected for security.")

    except Exception as e:
        logger.error(f"Malware scan failed: {e}")
        raise ValueError(f"Malware scan failed: {e}")


def sanitize_svg(file_path: str) -> None:
    """
    Sanitize SVG file to prevent XSS attacks

    SVG files can contain <script> tags → XSS vulnerability

    Attack Example:
        <svg><script>alert('XSS')</script></svg>

    Defense: Remove all <script> tags from SVG
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()

        # Remove <script> tags (simple regex - use lxml for production)
        content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL | re.IGNORECASE)

        # Remove event handlers (onclick, onload, etc.)
        content = re.sub(r'\son\w+\s*=\s*["\'][^"\']*["\']', '', content, flags=re.IGNORECASE)

        # Remove javascript: protocol
        content = re.sub(r'javascript:', '', content, flags=re.IGNORECASE)

        with open(file_path, 'w') as f:
            f.write(content)

        logger.info(f"SVG sanitized: {file_path}")

    except Exception as e:
        logger.error(f"SVG sanitization failed: {e}")
        raise ValueError(f"SVG sanitization failed: {e}")


def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of file (for deduplication)"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# ============================================================================
# STORAGE ADAPTERS
# ============================================================================

class S3StorageAdapter:
    """
    AWS S3 storage adapter

    Features:
    - Server-side encryption (AES-256)
    - Private buckets (no public access)
    - CloudFront CDN integration
    - Lifecycle policies
    """

    def __init__(self):
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            region_name=os.environ.get('AWS_REGION', 'us-east-1')
        )
        self.bucket_name = os.environ.get('S3_BUCKET_NAME')

        if not self.bucket_name:
            raise ValueError("S3_BUCKET_NAME environment variable not set")

        logger.info(f"[STORAGE] S3 adapter initialized: {self.bucket_name}")

    async def upload(
        self,
        file_path: str,
        destination_key: str,
        content_type: str,
        metadata: Dict[str, str] = None
    ) -> str:
        """
        Upload file to S3

        Security:
        - Server-side encryption enabled (AES-256)
        - Private bucket (no public read access)
        - HTTPS only

        Returns:
            URL of uploaded file
        """
        try:
            # Upload with server-side encryption
            self.s3_client.upload_file(
                file_path,
                self.bucket_name,
                destination_key,
                ExtraArgs={
                    'ContentType': content_type,
                    'ServerSideEncryption': 'AES256',  # Encrypt at rest
                    'Metadata': metadata or {},
                    'CacheControl': 'max-age=31536000',  # Cache for 1 year
                    'ContentDisposition': 'attachment'  # Prevent XSS (force download)
                }
            )

            # Generate URL
            # Note: Use CloudFront distribution URL in production
            cloudfront_domain = os.environ.get('CLOUDFRONT_DOMAIN')
            if cloudfront_domain:
                url = f"https://{cloudfront_domain}/{destination_key}"
            else:
                url = f"https://{self.bucket_name}.s3.amazonaws.com/{destination_key}"

            logger.info(f"[STORAGE] S3 upload successful: {destination_key}")

            return url

        except ClientError as e:
            logger.error(f"[STORAGE] S3 upload failed: {e}")
            raise ValueError(f"S3 upload failed: {e}")

    async def delete(self, file_key: str) -> bool:
        """Delete file from S3"""
        try:
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=file_key)
            logger.info(f"[STORAGE] S3 delete successful: {file_key}")
            return True
        except ClientError as e:
            logger.error(f"[STORAGE] S3 delete failed: {e}")
            raise ValueError(f"S3 delete failed: {e}")

    async def generate_presigned_url(
        self,
        file_key: str,
        expiration: int = 3600
    ) -> str:
        """Generate presigned URL for temporary access"""
        try:
            url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': self.bucket_name, 'Key': file_key},
                ExpiresIn=expiration
            )
            return url
        except ClientError as e:
            logger.error(f"[STORAGE] Presigned URL generation failed: {e}")
            raise ValueError(f"Presigned URL generation failed: {e}")


class CloudinaryStorageAdapter:
    """
    Cloudinary storage adapter

    Features:
    - Automatic image optimization (compress 50-70%)
    - Responsive images (auto-generate sizes)
    - CDN delivery (fast global access)
    - On-the-fly transformations
    """

    def __init__(self):
        cloudinary.config(
            cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
            api_key=os.environ.get('CLOUDINARY_API_KEY'),
            api_secret=os.environ.get('CLOUDINARY_API_SECRET'),
            secure=True
        )

        logger.info("[STORAGE] Cloudinary adapter initialized")

    async def upload(
        self,
        file_path: str,
        folder: str = 'uploads',
        resource_type: str = 'auto'
    ) -> Dict[str, Any]:
        """
        Upload file to Cloudinary

        Features:
        - Auto-optimize images (quality=auto)
        - Auto-format (WebP for supported browsers)
        - Responsive breakpoints (5 sizes)

        Returns:
            {
                'url': 'https://res.cloudinary.com/...',
                'public_id': 'uploads/abc123',
                'width': 1920,
                'height': 1080,
                'format': 'jpg',
                'bytes': 123456
            }
        """
        try:
            result = cloudinary.uploader.upload(
                file_path,
                folder=folder,
                use_filename=False,
                unique_filename=True,
                resource_type=resource_type,  # 'image', 'video', 'raw', 'auto'

                # Optimization
                quality='auto',  # AI-based compression
                fetch_format='auto',  # Auto WebP/AVIF

                # Responsive images (for images only)
                responsive_breakpoints={
                    'create_derived': True,
                    'bytes_step': 20000,
                    'min_width': 200,
                    'max_width': 1920,
                    'max_images': 5
                } if resource_type in ['image', 'auto'] else None
            )

            logger.info(f"[STORAGE] Cloudinary upload successful: {result['public_id']}")

            return {
                'url': result['secure_url'],
                'public_id': result['public_id'],
                'width': result.get('width'),
                'height': result.get('height'),
                'format': result.get('format'),
                'bytes': result.get('bytes'),
                'provider': StorageProvider.CLOUDINARY
            }

        except Exception as e:
            logger.error(f"[STORAGE] Cloudinary upload failed: {e}")
            raise ValueError(f"Cloudinary upload failed: {e}")

    async def delete(self, public_id: str, resource_type: str = 'image') -> bool:
        """Delete file from Cloudinary"""
        try:
            result = cloudinary.uploader.destroy(public_id, resource_type=resource_type)
            success = result.get('result') == 'ok'
            if success:
                logger.info(f"[STORAGE] Cloudinary delete successful: {public_id}")
            return success
        except Exception as e:
            logger.error(f"[STORAGE] Cloudinary delete failed: {e}")
            raise ValueError(f"Cloudinary delete failed: {e}")


class LocalStorageAdapter:
    """
    Local disk storage adapter

    WARNING: For development only!
    Security risks:
    - Path traversal vulnerabilities
    - No redundancy (disk failure = data loss)
    - No CDN (slow for global users)

    Use S3/Cloudinary in production!
    """

    def __init__(self):
        self.upload_dir = os.environ.get('LOCAL_UPLOAD_DIR', './uploads')
        os.makedirs(self.upload_dir, exist_ok=True)

        logger.warning("[STORAGE] Local storage adapter initialized (DEV ONLY)")

    async def upload(
        self,
        file_path: str,
        destination_path: str
    ) -> str:
        """
        Upload file to local disk

        Returns:
            Relative path to file
        """
        try:
            full_path = os.path.join(self.upload_dir, destination_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)

            shutil.copy2(file_path, full_path)

            logger.info(f"[STORAGE] Local upload successful: {destination_path}")

            # Return relative URL
            return f"/uploads/{destination_path}"

        except Exception as e:
            logger.error(f"[STORAGE] Local upload failed: {e}")
            raise ValueError(f"Local upload failed: {e}")

    async def delete(self, file_path: str) -> bool:
        """Delete file from local disk"""
        try:
            full_path = os.path.join(self.upload_dir, file_path)
            if os.path.exists(full_path):
                os.remove(full_path)
                logger.info(f"[STORAGE] Local delete successful: {file_path}")
                return True
            return False
        except Exception as e:
            logger.error(f"[STORAGE] Local delete failed: {e}")
            raise ValueError(f"Local delete failed: {e}")


# ============================================================================
# FILE UPLOAD SERVICE
# ============================================================================

class FileUploadService:
    """
    Main file upload service with multi-storage support

    Features:
    - Multi-storage (S3, Cloudinary, Local)
    - Security validation (type, size, malware)
    - Automatic provider routing (images → Cloudinary, files → S3)
    """

    def __init__(self):
        self.storage_adapters = {}

        # Initialize storage adapters
        try:
            self.storage_adapters[StorageProvider.S3] = S3StorageAdapter()
        except Exception as e:
            logger.warning(f"S3 adapter not available: {e}")

        try:
            self.storage_adapters[StorageProvider.CLOUDINARY] = CloudinaryStorageAdapter()
        except Exception as e:
            logger.warning(f"Cloudinary adapter not available: {e}")

        try:
            self.storage_adapters[StorageProvider.LOCAL] = LocalStorageAdapter()
        except Exception as e:
            logger.warning(f"Local adapter not available: {e}")

        if not self.storage_adapters:
            raise ValueError("No storage adapters configured")

        logger.info("[UPLOAD] File upload service initialized")

    def get_storage_provider(self, mime_type: str) -> StorageProvider:
        """
        Route file to appropriate storage provider

        Routing logic:
        - Images/Videos → Cloudinary (optimization + CDN)
        - Documents/Files → S3 (cheap storage)
        - Fallback → Local (development)
        """
        # Check environment override
        default_provider = os.environ.get('DEFAULT_STORAGE_PROVIDER', 'auto')

        if default_provider != 'auto':
            return StorageProvider(default_provider)

        # Auto-routing
        if mime_type.startswith('image/') or mime_type.startswith('video/'):
            if StorageProvider.CLOUDINARY in self.storage_adapters:
                return StorageProvider.CLOUDINARY

        if StorageProvider.S3 in self.storage_adapters:
            return StorageProvider.S3

        if StorageProvider.LOCAL in self.storage_adapters:
            return StorageProvider.LOCAL

        raise ValueError("No suitable storage provider available")

    async def upload(
        self,
        file: UploadFile,
        folder: str = 'uploads',
        metadata: Dict[str, str] = None
    ) -> UploadResponse:
        """
        Upload file with security validation

        Steps:
        1. Read file to memory
        2. Validate file type (MIME + magic bytes)
        3. Validate file size
        4. Sanitize filename
        5. Save to temp file
        6. Scan for malware
        7. Sanitize SVG (if applicable)
        8. Upload to storage provider
        9. Clean up temp file
        10. Return URL

        Returns:
            UploadResponse with file URL and metadata
        """
        temp_file_path = None

        try:
            # 1. Read file to memory
            file_bytes = await file.read()
            file_size = len(file_bytes)

            logger.info(f"[UPLOAD] Processing file: {file.filename} ({file_size} bytes)")

            # 2. Validate file type (MIME + magic bytes)
            actual_mime = validate_file_type(file_bytes, file.content_type)
            file_type_category = get_file_type_category(actual_mime)

            # 3. Validate file size
            validate_file_size(file_size, file_type_category)

            # 4. Sanitize filename
            safe_filename = sanitize_filename(file.filename)
            file_id = str(uuid.uuid4())

            # 5. Save to temp file (for malware scan)
            temp_dir = tempfile.gettempdir()
            temp_file_path = os.path.join(temp_dir, safe_filename)

            with open(temp_file_path, 'wb') as f:
                f.write(file_bytes)

            # 6. Scan for malware
            if os.environ.get('ENABLE_MALWARE_SCAN', 'true').lower() == 'true':
                scan_for_malware(temp_file_path)

            # 7. Sanitize SVG (prevent XSS)
            if actual_mime == 'image/svg+xml':
                sanitize_svg(temp_file_path)

            # 8. Upload to storage provider
            provider = self.get_storage_provider(actual_mime)
            storage_adapter = self.storage_adapters[provider]

            # Calculate file hash (for deduplication)
            file_hash = calculate_file_hash(temp_file_path)

            if provider == StorageProvider.CLOUDINARY and file_type_category in ['image', 'video']:
                # Upload to Cloudinary (with optimization)
                result = await storage_adapter.upload(
                    temp_file_path,
                    folder=folder,
                    resource_type='auto'
                )
                url = result['url']
                upload_metadata = result

            elif provider == StorageProvider.S3:
                # Upload to S3
                destination_key = f"{folder}/{safe_filename}"
                url = await storage_adapter.upload(
                    temp_file_path,
                    destination_key,
                    actual_mime,
                    metadata={
                        'original_filename': file.filename,
                        'file_id': file_id,
                        'file_hash': file_hash,
                        **(metadata or {})
                    }
                )
                upload_metadata = {'s3_key': destination_key}

            elif provider == StorageProvider.LOCAL:
                # Upload to local disk (dev only)
                destination_path = f"{folder}/{safe_filename}"
                url = await storage_adapter.upload(temp_file_path, destination_path)
                upload_metadata = {'local_path': destination_path}

            else:
                raise ValueError(f"Unsupported provider: {provider}")

            # 9. Clean up temp file
            if temp_file_path and os.path.exists(temp_file_path):
                os.remove(temp_file_path)

            logger.info(f"[UPLOAD] Upload successful: {safe_filename} → {url}")

            # 10. Return response
            return UploadResponse(
                success=True,
                url=url,
                filename=safe_filename,
                size=file_size,
                content_type=actual_mime,
                provider=provider,
                file_id=file_id,
                metadata={
                    'original_filename': file.filename,
                    'file_hash': file_hash,
                    'file_type': file_type_category,
                    'uploaded_at': datetime.utcnow().isoformat(),
                    **upload_metadata,
                    **(metadata or {})
                }
            )

        except ValueError as e:
            # Validation error (user error)
            logger.warning(f"[UPLOAD] Validation failed: {e}")
            raise HTTPException(status_code=400, detail=str(e))

        except Exception as e:
            # Server error
            logger.error(f"[UPLOAD] Upload failed: {e}")
            raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

        finally:
            # Ensure temp file is cleaned up
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except Exception as e:
                    logger.error(f"[UPLOAD] Failed to clean up temp file: {e}")


# ============================================================================
# FASTAPI INTEGRATION EXAMPLE
# ============================================================================

async def example_fastapi_integration():
    """Example FastAPI integration"""
    app = FastAPI(title="File Upload API")

    # Initialize upload service
    upload_service = FileUploadService()

    @app.post("/api/upload", response_model=UploadResponse)
    async def upload_file(
        file: UploadFile = File(...),
        folder: str = 'uploads'
    ):
        """
        Upload file with security validation

        Validates:
        - File type (MIME + magic bytes)
        - File size (prevents DoS)
        - Filename (prevents path traversal)
        - Malware (ClamAV scan)

        Returns:
            URL of uploaded file
        """
        result = await upload_service.upload(file, folder=folder)
        return result

    @app.post("/api/upload/image", response_model=UploadResponse)
    async def upload_image(file: UploadFile = File(...)):
        """Upload image (routes to Cloudinary for optimization)"""
        # Validate it's actually an image
        file_bytes = await file.read()
        await file.seek(0)

        actual_mime = validate_file_type(file_bytes, file.content_type)

        if not actual_mime.startswith('image/'):
            raise HTTPException(status_code=400, detail="File is not an image")

        result = await upload_service.upload(file, folder='images')
        return result

    @app.get("/health")
    async def health_check():
        """Health check endpoint"""
        return {
            'status': 'healthy',
            'storage_providers': list(upload_service.storage_adapters.keys())
        }

    return app


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    'FileUploadService',
    'StorageProvider',
    'FileType',
    'UploadResponse',
    'S3StorageAdapter',
    'CloudinaryStorageAdapter',
    'LocalStorageAdapter',
    'sanitize_filename',
    'validate_file_type',
    'validate_file_size',
    'scan_for_malware',
]
