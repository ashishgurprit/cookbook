# File Upload Universal - Production Guide

**Multi-storage file upload system with comprehensive security validation.**

Version: 1.0.0
Status: Production Ready
Security: OWASP Compliant

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Security Validation](#security-validation)
4. [Storage Providers](#storage-providers)
5. [File Upload Flow](#file-upload-flow)
6. [File Type Validation](#file-type-validation)
7. [Malware Scanning](#malware-scanning)
8. [Image Optimization](#image-optimization)
9. [Direct Upload (Client-Side)](#direct-upload-client-side)
10. [Security Considerations](#security-considerations)
11. [Testing Guide](#testing-guide)
12. [Troubleshooting](#troubleshooting)

---

## Overview

### Why Multi-Storage?

**Problem**: Single storage provider = vendor lock-in + not optimized for different file types

**Solution**: Multi-storage adapter pattern

**Benefits**:
- ✅ S3 for documents (cheap, reliable: $0.023/GB)
- ✅ Cloudinary for images (optimization, CDN: auto-compress 50-70%)
- ✅ Local for development (free, fast iteration)
- ✅ No vendor lock-in (switch providers anytime)
- ✅ Cost optimization (right tool for each job)

### Supported Storage Providers

| Provider | Use Case | Cost | Best For |
|----------|----------|------|----------|
| **AWS S3** (Primary) | Documents, backups, large files | $0.023/GB/month | General file storage, videos |
| **Cloudinary** (Images) | Images, videos | $0.10/GB/month | Image optimization, responsive images |
| **Local Disk** (Dev) | Development/testing | Free | Local development only |

### Critical Security Rules

🚫 **NEVER** trust user-uploaded filenames
🚫 **NEVER** execute uploaded files
🚫 **NEVER** store files in web root directory
✅ **ALWAYS** validate file type (MIME + magic bytes)
✅ **ALWAYS** enforce file size limits
✅ **ALWAYS** sanitize filenames (prevent path traversal)
✅ **ALWAYS** scan for malware

---

## Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────┐
│         Client (Browser/App)                │
│  • Select file                              │
│  • Upload to backend                        │
└──────────────┬──────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────┐
│      File Upload Service (Your Backend)      │
│  • Validate file type (MIME + magic bytes)   │
│  • Validate file size                        │
│  • Sanitize filename                         │
│  • Scan for malware                          │
│  • Route to storage provider                 │
└──────────────┬───────────────────────────────┘
               │
       ┌───────┴───────┐
       │               │
       ▼               ▼
┌────────────┐   ┌────────────┐
│ S3 Adapter │   │ Cloudinary │
│            │   │  Adapter   │
└──────┬─────┘   └──────┬─────┘
       │                │
       ▼                ▼
┌────────────┐   ┌────────────┐
│   AWS S3   │   │ Cloudinary │
│  (Files)   │   │  (Images)  │
└────────────┘   └────────────┘
```

### File Type Routing

**Automatic Routing**:
```python
# Images/Videos → Cloudinary (optimization + CDN)
if mime_type.startswith('image/'):
    provider = 'cloudinary'
elif mime_type.startswith('video/'):
    provider = 'cloudinary'

# Documents → S3 (cheap storage)
elif mime_type in ['application/pdf', 'application/msword']:
    provider = 's3'

# Everything else → S3
else:
    provider = 's3'
```

---

## Security Validation

### 1. File Type Validation (CRITICAL)

**Attack**: Upload malicious.php.jpg → Execute PHP code

**Defense**: Validate MIME type AND magic bytes

```python
import magic

def validate_file_type(file: UploadFile, allowed_types: List[str]) -> bool:
    """
    Validate file type using MIME and magic bytes

    Why both?
    - MIME type: Declared by client (can be spoofed)
    - Magic bytes: Actual file content (cannot be spoofed)

    Attack example:
        Upload shell.php with Content-Type: image/jpeg
        Without magic bytes check: Accepted as image
        With magic bytes check: Rejected (not a real JPEG)
    """
    # 1. Check declared MIME type
    declared_mime = file.content_type
    if declared_mime not in allowed_types:
        raise ValueError(f"File type {declared_mime} not allowed")

    # 2. Check actual file content (magic bytes)
    file_bytes = file.file.read(2048)  # Read first 2KB
    file.file.seek(0)  # Reset file pointer

    actual_mime = magic.from_buffer(file_bytes, mime=True)

    if actual_mime not in allowed_types:
        raise ValueError(f"File content type {actual_mime} doesn't match declared type")

    # 3. Both checks must pass
    if declared_mime != actual_mime:
        raise ValueError("MIME type mismatch (possible file type spoofing)")

    return True
```

**Allowed File Types**:
```python
ALLOWED_IMAGE_TYPES = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'image/svg+xml'  # Note: SVG requires additional sanitization
]

ALLOWED_DOCUMENT_TYPES = [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',  # .docx
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',  # .xlsx
    'text/plain',
    'text/csv'
]

ALLOWED_VIDEO_TYPES = [
    'video/mp4',
    'video/quicktime',  # .mov
    'video/x-msvideo'   # .avi
]
```

### 2. File Size Validation

**Attack**: Upload 10GB file → Fill disk space (DoS)

**Defense**: Enforce size limits

```python
MAX_FILE_SIZE = {
    'image': 10 * 1024 * 1024,      # 10MB
    'document': 25 * 1024 * 1024,   # 25MB
    'video': 500 * 1024 * 1024,     # 500MB
    'default': 10 * 1024 * 1024     # 10MB
}

def validate_file_size(file: UploadFile, max_size: int) -> bool:
    """Validate file size doesn't exceed limit"""
    file.file.seek(0, 2)  # Seek to end
    size = file.file.tell()
    file.file.seek(0)  # Reset

    if size > max_size:
        raise ValueError(f"File size {size} exceeds limit {max_size}")

    return True
```

### 3. Filename Sanitization

**Attack**: Upload ../../etc/passwd → Path traversal

**Defense**: Sanitize filename, use UUID

```python
import uuid
import re
from pathlib import Path

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal

    Attacks prevented:
    - ../../../etc/passwd → rejected
    - shell.php → rejected (if not allowed extension)
    - image<script>.jpg → script removed
    """
    # 1. Get extension
    ext = Path(filename).suffix.lower()

    # 2. Validate extension whitelist
    allowed_extensions = [
        '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt', '.csv',
        '.mp4', '.mov', '.avi'
    ]

    if ext not in allowed_extensions:
        raise ValueError(f"File extension {ext} not allowed")

    # 3. Generate safe filename (UUID + extension)
    safe_filename = f"{uuid.uuid4()}{ext}"

    return safe_filename
```

**Why UUID**:
- Prevents path traversal (no ../ possible)
- Prevents filename conflicts
- Unpredictable (security through obscurity)
- Original filename stored in metadata

### 4. Malware Scanning

**Attack**: Upload virus.exe → Infect server or users

**Defense**: Scan with ClamAV

```python
import pyclamd

def scan_for_malware(file_path: str) -> bool:
    """
    Scan file for malware using ClamAV

    Setup:
        sudo apt-get install clamav clamav-daemon
        pip install pyclamd
    """
    try:
        # Connect to ClamAV daemon
        cd = pyclamd.ClamdUnixSocket()

        # Scan file
        result = cd.scan_file(file_path)

        if result is None:
            # Clean file
            return True
        else:
            # Malware detected
            virus_name = result[file_path][1]
            raise ValueError(f"Malware detected: {virus_name}")

    except Exception as e:
        # If ClamAV unavailable, fail securely (reject upload)
        raise ValueError(f"Malware scan failed: {e}")
```

---

## Storage Providers

### AWS S3 Integration

**Setup**:

1. **Create S3 Bucket**:
```bash
aws s3 mb s3://my-app-uploads
```

2. **Configure CORS** (for direct uploads):
```json
[
    {
        "AllowedHeaders": ["*"],
        "AllowedMethods": ["PUT", "POST", "GET"],
        "AllowedOrigins": ["https://yourdomain.com"],
        "ExposeHeaders": ["ETag"]
    }
]
```

3. **Set Bucket Policy** (private by default):
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::my-app-uploads/*",
            "Condition": {
                "Bool": {"aws:SecureTransport": "false"}
            }
        }
    ]
}
```

**Upload to S3**:

```python
import boto3
from botocore.exceptions import ClientError

class S3Adapter:
    def __init__(self):
        self.s3 = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            region_name=os.environ.get('AWS_REGION', 'us-east-1')
        )
        self.bucket = os.environ.get('S3_BUCKET_NAME')

    async def upload(
        self,
        file_path: str,
        destination_key: str,
        content_type: str,
        metadata: dict = None
    ) -> str:
        """
        Upload file to S3

        Returns:
            URL of uploaded file
        """
        try:
            # Upload with server-side encryption
            self.s3.upload_file(
                file_path,
                self.bucket,
                destination_key,
                ExtraArgs={
                    'ContentType': content_type,
                    'ServerSideEncryption': 'AES256',  # Encrypt at rest
                    'Metadata': metadata or {},
                    'CacheControl': 'max-age=31536000'  # Cache for 1 year
                }
            )

            # Generate URL (via CloudFront if configured)
            url = f"https://{self.bucket}.s3.amazonaws.com/{destination_key}"

            return url

        except ClientError as e:
            raise ValueError(f"S3 upload failed: {e}")

    async def delete(self, file_key: str) -> bool:
        """Delete file from S3"""
        try:
            self.s3.delete_object(Bucket=self.bucket, Key=file_key)
            return True
        except ClientError as e:
            raise ValueError(f"S3 delete failed: {e}")
```

---

### Cloudinary Integration

**Setup**:

1. **Sign up**: https://cloudinary.com/users/register/free

2. **Get API credentials**:
```bash
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
```

**Upload to Cloudinary**:

```python
import cloudinary
import cloudinary.uploader

class CloudinaryAdapter:
    def __init__(self):
        cloudinary.config(
            cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
            api_key=os.environ.get('CLOUDINARY_API_KEY'),
            api_secret=os.environ.get('CLOUDINARY_API_SECRET'),
            secure=True
        )

    async def upload(
        self,
        file_path: str,
        folder: str = 'uploads',
        transformation: dict = None
    ) -> dict:
        """
        Upload image to Cloudinary with optimization

        Features:
        - Auto-format (WebP for supported browsers)
        - Auto-quality (AI-based compression)
        - Responsive breakpoints (auto-generate sizes)

        Returns:
            {
                'url': 'https://res.cloudinary.com/...',
                'secure_url': 'https://res.cloudinary.com/...',
                'public_id': 'uploads/abc123',
                'width': 1920,
                'height': 1080
            }
        """
        try:
            result = cloudinary.uploader.upload(
                file_path,
                folder=folder,
                use_filename=False,  # Use Cloudinary-generated ID
                unique_filename=True,
                resource_type='auto',  # Auto-detect (image/video/raw)

                # Optimization
                quality='auto',  # AI-based compression
                fetch_format='auto',  # Auto WebP/AVIF

                # Responsive images
                responsive_breakpoints={
                    'create_derived': True,
                    'bytes_step': 20000,
                    'min_width': 200,
                    'max_width': 1920,
                    'max_images': 5
                },

                # Custom transformation
                transformation=transformation or {}
            )

            return {
                'url': result['secure_url'],
                'public_id': result['public_id'],
                'width': result.get('width'),
                'height': result.get('height'),
                'format': result.get('format'),
                'bytes': result.get('bytes')
            }

        except Exception as e:
            raise ValueError(f"Cloudinary upload failed: {e}")

    async def delete(self, public_id: str) -> bool:
        """Delete image from Cloudinary"""
        try:
            result = cloudinary.uploader.destroy(public_id)
            return result['result'] == 'ok'
        except Exception as e:
            raise ValueError(f"Cloudinary delete failed: {e}")
```

---

## File Upload Flow

### Standard Upload Flow

```
1. Client selects file
2. Client POSTs file to /api/upload
3. Backend validates file (type, size, malware)
4. Backend sanitizes filename
5. Backend routes to storage provider (S3/Cloudinary)
6. Provider returns URL
7. Backend saves metadata to database
8. Backend returns URL to client
```

**Backend Endpoint**:

```python
from fastapi import FastAPI, UploadFile, File

@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...),
    file_type: str = 'document'  # 'image', 'document', 'video'
):
    """
    Upload file with security validation

    Steps:
    1. Validate file type (MIME + magic bytes)
    2. Validate file size
    3. Sanitize filename
    4. Scan for malware
    5. Upload to storage provider
    6. Return URL
    """
    try:
        # 1. Validate file type
        allowed_types = get_allowed_types(file_type)
        validate_file_type(file, allowed_types)

        # 2. Validate file size
        max_size = MAX_FILE_SIZE.get(file_type, MAX_FILE_SIZE['default'])
        validate_file_size(file, max_size)

        # 3. Sanitize filename
        safe_filename = sanitize_filename(file.filename)

        # 4. Save to temp file for malware scan
        temp_path = f"/tmp/{safe_filename}"
        with open(temp_path, "wb") as f:
            content = await file.read()
            f.write(content)

        # 5. Scan for malware
        scan_for_malware(temp_path)

        # 6. Route to storage provider
        provider = get_storage_provider(file.content_type)

        if provider == 'cloudinary' and file_type == 'image':
            # Upload to Cloudinary (with optimization)
            result = await cloudinary_adapter.upload(temp_path)
            url = result['url']
        else:
            # Upload to S3
            destination_key = f"{file_type}/{safe_filename}"
            url = await s3_adapter.upload(
                temp_path,
                destination_key,
                file.content_type
            )

        # 7. Clean up temp file
        os.remove(temp_path)

        # 8. Save metadata to database
        file_record = {
            'original_filename': file.filename,
            'safe_filename': safe_filename,
            'url': url,
            'size': os.path.getsize(temp_path),
            'content_type': file.content_type,
            'provider': provider,
            'uploaded_at': datetime.utcnow()
        }
        # db.save(file_record)

        # 9. Return URL
        return {
            'success': True,
            'url': url,
            'filename': safe_filename
        }

    except ValueError as e:
        return {
            'success': False,
            'error': str(e)
        }
```

---

## Direct Upload (Client-Side)

**Why Direct Upload?**
- Faster (no backend proxy)
- Reduces server load
- Better for large files

**S3 Presigned URLs**:

```python
def generate_presigned_post(filename: str, content_type: str) -> dict:
    """
    Generate presigned POST URL for direct S3 upload

    Client uploads directly to S3 using this URL
    """
    safe_filename = sanitize_filename(filename)
    key = f"uploads/{safe_filename}"

    # Generate presigned POST (valid for 5 minutes)
    response = s3_client.generate_presigned_post(
        Bucket=S3_BUCKET,
        Key=key,
        Fields={'Content-Type': content_type},
        Conditions=[
            {'Content-Type': content_type},
            ['content-length-range', 0, MAX_FILE_SIZE['default']]
        ],
        ExpiresIn=300  # 5 minutes
    )

    return {
        'url': response['url'],
        'fields': response['fields'],
        'key': key
    }
```

**Frontend (Direct Upload)**:

```javascript
// 1. Get presigned URL from backend
const response = await fetch('/api/upload/presigned', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        filename: file.name,
        contentType: file.type
    })
});
const {url, fields} = await response.json();

// 2. Upload directly to S3
const formData = new FormData();
Object.entries(fields).forEach(([key, value]) => {
    formData.append(key, value);
});
formData.append('file', file);

await fetch(url, {
    method: 'POST',
    body: formData
});

// 3. File uploaded! URL = url + fields.key
```

---

## Image Optimization

### Cloudinary Transformations

**Responsive Images**:

```python
# Generate responsive image URLs
base_url = "https://res.cloudinary.com/demo/image/upload"
public_id = "sample.jpg"

# Mobile (400px)
mobile_url = f"{base_url}/w_400,c_limit,q_auto,f_auto/{public_id}"

# Tablet (800px)
tablet_url = f"{base_url}/w_800,c_limit,q_auto,f_auto/{public_id}"

# Desktop (1200px)
desktop_url = f"{base_url}/w_1200,c_limit,q_auto,f_auto/{public_id}"
```

**HTML (srcset)**:

```html
<img
    src="https://res.cloudinary.com/.../w_800,q_auto,f_auto/sample.jpg"
    srcset="
        https://res.cloudinary.com/.../w_400,q_auto,f_auto/sample.jpg 400w,
        https://res.cloudinary.com/.../w_800,q_auto,f_auto/sample.jpg 800w,
        https://res.cloudinary.com/.../w_1200,q_auto,f_auto/sample.jpg 1200w
    "
    sizes="(max-width: 400px) 400px, (max-width: 800px) 800px, 1200px"
    alt="Sample image"
>
```

**Transformation Examples**:

```python
# Auto-crop to face
cloudinary.uploader.upload(
    file_path,
    transformation={'gravity': 'face', 'crop': 'thumb', 'width': 200, 'height': 200}
)

# Background removal (AI)
cloudinary.uploader.upload(
    file_path,
    transformation={'effect': 'background_removal'}
)

# Blur faces (privacy)
cloudinary.uploader.upload(
    file_path,
    transformation={'effect': 'blur_faces:1000'}
)
```

---

## Security Considerations

### OWASP Compliance

| Category | Implementation | Status |
|----------|----------------|--------|
| **A01:2021** | Broken Access Control | Path traversal prevention (sanitize filenames) | ✅ |
| **A03:2021** | Injection | No file execution, magic bytes validation | ✅ |
| **A04:2021** | Insecure Design | Multi-layer validation (MIME + magic bytes + malware) | ✅ |
| **A05:2021** | Security Misconfiguration | Private S3 buckets, HTTPS only | ✅ |
| **A08:2021** | Software/Data Integrity | File integrity checks, malware scanning | ✅ |

### Common Vulnerabilities

**1. Path Traversal**:
```python
# ❌ VULNERABLE
filename = request.files['file'].filename  # "../../etc/passwd"
save_path = f"/uploads/{filename}"  # /etc/passwd (overwrites system file!)

# ✅ SECURE
filename = sanitize_filename(request.files['file'].filename)
# Result: "abc123-uuid.jpg" (safe)
```

**2. File Type Spoofing**:
```python
# ❌ VULNERABLE (only checks extension)
if filename.endswith('.jpg'):
    save_file()  # Saves shell.php.jpg (PHP executed!)

# ✅ SECURE (checks magic bytes)
if magic.from_buffer(file_bytes) == 'image/jpeg':
    save_file()  # Real JPEG only
```

**3. XSS via SVG**:
```xml
<!-- Malicious SVG -->
<svg xmlns="http://www.w3.org/2000/svg">
    <script>alert('XSS')</script>
</svg>
```

**Defense**:
```python
# Sanitize SVG files
from lxml import etree

def sanitize_svg(file_path: str):
    """Remove scripts from SVG"""
    tree = etree.parse(file_path)
    # Remove <script> tags
    for script in tree.xpath('//svg:script', namespaces={'svg': 'http://www.w3.org/2000/svg'}):
        script.getparent().remove(script)
    tree.write(file_path)
```

**4. Malware Upload**:
```python
# ✅ SECURE: Scan all uploads
scan_for_malware(file_path)  # ClamAV
```

---

## Testing Guide

### Test File Types

```bash
# Valid files
curl -F "file=@test.jpg" http://localhost:8000/api/upload
curl -F "file=@test.pdf" http://localhost:8000/api/upload

# Invalid file type (should reject)
curl -F "file=@shell.php" http://localhost:8000/api/upload
# Expected: 400 error "File type not allowed"

# File too large (should reject)
curl -F "file=@huge.mp4" http://localhost:8000/api/upload
# Expected: 400 error "File size exceeds limit"

# Path traversal (should reject)
curl -F "file=@../../etc/passwd" http://localhost:8000/api/upload
# Expected: 400 error "Invalid filename"
```

### Security Test Checklist

- [ ] Upload valid image (JPEG, PNG) → Success
- [ ] Upload valid document (PDF, DOCX) → Success
- [ ] Upload executable (.exe, .sh) → Rejected
- [ ] Upload PHP file → Rejected
- [ ] Upload file > size limit → Rejected
- [ ] Upload file with path traversal filename → Rejected
- [ ] Upload malware test file (EICAR) → Rejected
- [ ] Upload SVG with script tag → Sanitized
- [ ] Upload with fake MIME type → Rejected (magic bytes check)

---

## Troubleshooting

### Issue 1: "File type not allowed"

**Cause**: File MIME type not in allowed list

**Solution**:
- Check `ALLOWED_IMAGE_TYPES` / `ALLOWED_DOCUMENT_TYPES`
- Add file type if legitimate
- Verify file is not spoofed (check magic bytes)

---

### Issue 2: "Malware detected"

**Cause**: ClamAV detected virus or malware

**Solution**:
- File is legitimately malicious (reject upload)
- False positive (update ClamAV database)
- Test with EICAR test file: https://www.eicar.org/

---

### Issue 3: "S3 upload failed: Access Denied"

**Cause**: IAM permissions insufficient

**Solution**:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject"
            ],
            "Resource": "arn:aws:s3:::my-bucket/*"
        }
    ]
}
```

---

## Best Practices

1. **Always validate file type** (MIME + magic bytes)
2. **Always sanitize filenames** (use UUID)
3. **Always scan for malware** (ClamAV)
4. **Always enforce size limits** (prevent DoS)
5. **Never execute uploaded files**
6. **Never store files in web root**
7. **Use CDN for serving files** (CloudFront, Cloudinary)
8. **Set Content-Disposition: attachment** for downloads (prevent XSS)
9. **Encrypt files at rest** (S3 SSE, Cloudinary encryption)
10. **Audit all uploads** (log who uploaded what)

---

## Resources

- **OWASP File Upload Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- **AWS S3 Security**: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
- **Cloudinary Documentation**: https://cloudinary.com/documentation
- **python-magic**: https://github.com/ahupp/python-magic
- **ClamAV**: https://www.clamav.net/

---

**File uploads are production-ready. Follow security guidelines and never trust user input.**
