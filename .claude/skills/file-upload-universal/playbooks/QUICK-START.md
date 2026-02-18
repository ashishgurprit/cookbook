# File Upload Universal - Quick Start Guide

**Time to Deploy**: 15 minutes
**Difficulty**: Easy
**Security**: Production-ready (OWASP compliant)

---

## What You'll Build

A secure multi-storage file upload system with:
- ✅ Automatic routing (images → Cloudinary, files → S3)
- ✅ Security validation (MIME + magic bytes + malware scan)
- ✅ XSS prevention (SVG sanitization)
- ✅ Path traversal prevention (UUID filenames)
- ✅ File optimization (Cloudinary transformations)
- ✅ Malware scanning (ClamAV integration)

---

## Step 1: Choose Storage Providers (2 minutes)

### Option A: Multi-Storage (Recommended for Production)

**Use Case**: Production apps with images + documents

**Providers**:
- **Cloudinary** → Images/videos (automatic optimization, CDN)
- **AWS S3** → Documents/archives (cheap storage, 99.999999999% durability)

**Cost**:
- Cloudinary: Free tier (25 credits/month = 25GB bandwidth)
- AWS S3: $0.023/GB/month storage + $0.09/GB transfer

**Routing**:
```
image/jpeg → Cloudinary (optimized, resized, CDN)
image/png → Cloudinary
video/mp4 → Cloudinary
application/pdf → S3 (cheap, durable)
application/zip → S3
```

### Option B: Cloudinary Only

**Use Case**: Image-heavy apps (photo sharing, social media)

**Providers**:
- Cloudinary for everything

**Benefits**:
- Automatic image optimization
- Responsive images (srcset)
- Transformations on-the-fly
- Built-in CDN

### Option C: S3 Only

**Use Case**: Document management, file sharing

**Providers**:
- AWS S3 for everything

**Benefits**:
- Cheapest storage
- 99.999999999% durability
- Versioning support
- Server-side encryption

### Option D: Local Storage (Dev Only)

**Use Case**: Local development, testing

**Providers**:
- Local filesystem

**Warning**: NOT for production (no redundancy, no CDN)

---

## Step 2: Install Dependencies (3 minutes)

### For FastAPI (Python)

```bash
# Install FastAPI upload service
pip install fastapi uvicorn python-multipart python-magic

# Install storage providers
pip install boto3  # AWS S3
pip install cloudinary  # Cloudinary

# Install security tools
pip install python-magic  # MIME type detection (magic bytes)

# Optional: ClamAV malware scanning
# macOS
brew install clamav
freshclam  # Update virus database

# Ubuntu/Debian
sudo apt-get install clamav clamav-daemon
sudo freshclam

# Install Python ClamAV client
pip install clamd
```

### For Express.js (Node.js)

```bash
# Install Express upload service
npm install express multer

# Install storage providers
npm install @aws-sdk/client-s3  # AWS S3
npm install cloudinary  # Cloudinary

# Install security tools
npm install file-type  # MIME type detection

# Optional: ClamAV scanning
npm install clamscan
```

---

## Step 3: Configure Environment (5 minutes)

### Multi-Storage Setup (Cloudinary + S3)

Create `.env`:

```bash
# Storage Configuration
STORAGE_MODE=multi  # Options: multi, cloudinary, s3, local

# Cloudinary (for images/videos)
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret

# AWS S3 (for documents)
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1
AWS_S3_BUCKET=your-bucket-name

# Security Settings
MAX_FILE_SIZE_MB=10  # Max file size (MB)
ALLOWED_EXTENSIONS=jpg,jpeg,png,gif,pdf,docx,xlsx,zip
ENABLE_MALWARE_SCAN=true  # Requires ClamAV
ENABLE_SVG_SANITIZATION=true  # Remove <script> from SVG

# Local Storage (dev only)
LOCAL_UPLOAD_DIR=/tmp/uploads
```

### Get Cloudinary Credentials

1. Sign up: https://cloudinary.com/users/register/free
2. Dashboard: https://cloudinary.com/console
3. Copy: Cloud Name, API Key, API Secret

### Get AWS S3 Credentials

1. AWS Console: https://console.aws.amazon.com/iam/
2. Create IAM user with S3 access
3. Create S3 bucket with private ACL
4. Enable server-side encryption (SSE-AES256)

**S3 Bucket Policy** (enforce HTTPS):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::your-bucket-name/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

---

## Step 4: Integrate Backend (3 minutes)

### FastAPI Integration

Copy `templates/backend/fastapi-upload.py` to your project:

```python
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi_upload import FileUploadService
import os

app = FastAPI()

# Initialize upload service
upload_service = FileUploadService(
    storage_mode=os.getenv('STORAGE_MODE', 'multi'),
    cloudinary_config={
        'cloud_name': os.getenv('CLOUDINARY_CLOUD_NAME'),
        'api_key': os.getenv('CLOUDINARY_API_KEY'),
        'api_secret': os.getenv('CLOUDINARY_API_SECRET'),
    },
    s3_config={
        'bucket_name': os.getenv('AWS_S3_BUCKET'),
        'region': os.getenv('AWS_REGION'),
    },
    max_file_size_mb=int(os.getenv('MAX_FILE_SIZE_MB', 10)),
    enable_malware_scan=os.getenv('ENABLE_MALWARE_SCAN', 'true') == 'true',
)

@app.post('/upload')
async def upload_file(file: UploadFile = File(...)):
    """
    Upload file with automatic routing:
    - Images/videos → Cloudinary (optimized)
    - Documents → S3 (cheap storage)
    """
    try:
        result = await upload_service.upload(file)
        return {
            'success': True,
            'url': result['url'],
            'file_id': result['file_id'],
            'storage_provider': result['provider'],
            'file_size': result['file_size'],
            'mime_type': result['mime_type'],
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail='Upload failed')

@app.delete('/upload/{file_id}')
async def delete_file(file_id: str):
    """Delete uploaded file"""
    await upload_service.delete(file_id)
    return {'success': True}

# Run: uvicorn main:app --reload
```

### Frontend Integration (Dropzone.js)

```html
<!DOCTYPE html>
<html>
<head>
  <link rel="stylesheet" href="https://unpkg.com/dropzone@5/dist/min/dropzone.min.css">
</head>
<body>
  <div id="file-dropzone" class="dropzone"></div>

  <script src="https://unpkg.com/dropzone@5/dist/min/dropzone.min.js"></script>
  <script>
    Dropzone.options.fileDropzone = {
      url: '/upload',
      maxFilesize: 10, // MB
      acceptedFiles: 'image/*,application/pdf,.docx,.xlsx,.zip',

      success: function(file, response) {
        console.log('Upload successful:', response.url);
        console.log('Provider:', response.storage_provider);

        // Display uploaded image
        if (response.mime_type.startsWith('image/')) {
          const img = document.createElement('img');
          img.src = response.url;
          img.style.width = '200px';
          document.body.appendChild(img);
        }
      },

      error: function(file, errorMessage) {
        console.error('Upload failed:', errorMessage);
        alert('Upload failed: ' + errorMessage);
      }
    };
  </script>
</body>
</html>
```

---

## Step 5: Test Upload Security (2 minutes)

### Run Security Tests

```bash
# Install pytest
pip install pytest pytest-asyncio python-magic

# Run all security tests (37 tests)
cd .claude/skills/file-upload-universal
pytest tests/test_security.py -v

# Run specific category
pytest tests/test_security.py -v -k "test_path_traversal"
pytest tests/test_security.py -v -k "test_mime_spoofing"
pytest tests/test_security.py -v -k "test_malware"
```

**Expected Output**:
```
========================================== test session starts ==========================================
collected 37 items

tests/test_security.py::TestPathTraversalPrevention::test_reject_parent_directory_traversal PASSED
tests/test_security.py::TestPathTraversalPrevention::test_reject_absolute_path PASSED
tests/test_security.py::TestMIMETypeSpoofing::test_detect_php_file_as_image PASSED
tests/test_security.py::TestMIMETypeSpoofing::test_jpeg_magic_bytes_validation PASSED
tests/test_security.py::TestFileSizeDoS::test_reject_oversized_image PASSED
tests/test_security.py::TestMalwareUploadPrevention::test_detect_eicar_test_file PASSED
tests/test_security.py::TestXSSPrevention::test_svg_script_tag_removed PASSED
...
========================================== 37 passed in 2.5s ===========================================
```

### Manual Test: Upload Image

```bash
# Start server
uvicorn main:app --reload

# Upload test image
curl -X POST http://localhost:8000/upload \
  -F "file=@test-image.jpg"

# Expected response:
{
  "success": true,
  "url": "https://res.cloudinary.com/your-cloud/image/upload/v1234567890/abc123.jpg",
  "file_id": "abc123",
  "storage_provider": "cloudinary",
  "file_size": 245678,
  "mime_type": "image/jpeg"
}
```

### Manual Test: Upload Malicious File (Should Fail)

```bash
# Test 1: Path traversal (should sanitize)
curl -X POST http://localhost:8000/upload \
  -F "file=@../../etc/passwd"
# Filename sanitized to UUID

# Test 2: MIME spoofing (should reject)
curl -X POST http://localhost:8000/upload \
  -F "file=@shell.php" \
  -H "Content-Type: image/jpeg"
# Rejected: Magic bytes don't match MIME type

# Test 3: SVG with XSS (should sanitize)
curl -X POST http://localhost:8000/upload \
  -F "file=@malicious.svg"
# <script> tags removed

# Test 4: Malware (should reject - if ClamAV enabled)
curl -X POST http://localhost:8000/upload \
  -F "file=@eicar.txt"
# Rejected: Malware detected
```

---

## Step 6: Production Checklist

### Security

- [ ] ClamAV malware scanning enabled
- [ ] SVG sanitization enabled (removes `<script>` tags)
- [ ] MIME type validation (declared + magic bytes)
- [ ] File size limits enforced
- [ ] Filename sanitization (UUID-based)
- [ ] HTTPS enforced (S3 bucket policy)

### Storage

- [ ] S3 bucket is private (not public)
- [ ] S3 server-side encryption enabled (SSE-AES256)
- [ ] Cloudinary upload preset configured
- [ ] Content-Disposition: attachment (prevent XSS)

### Monitoring

- [ ] Upload success rate tracked
- [ ] Failed uploads logged (with file hash, not filename)
- [ ] Storage provider failover tested
- [ ] Malware detection alerts configured

### Performance

- [ ] File size limits appropriate (10MB images, 500MB videos)
- [ ] Cloudinary transformations used (responsive images)
- [ ] CDN caching configured
- [ ] Upload progress tracking implemented

---

## Common Issues

### Issue: "Magic bytes validation failed"

**Cause**: File extension doesn't match actual file content

**Fix**: User uploaded `.jpg` file that's actually a `.png`

```python
# Solution: Trust magic bytes, not extension
actual_mime = magic.from_buffer(file_bytes, mime=True)
if actual_mime not in ALLOWED_MIME_TYPES:
    raise ValueError(f"File type not allowed: {actual_mime}")
```

### Issue: "Malware detected"

**Cause**: ClamAV detected malware signature

**Fix**: File is likely malicious. Reject upload.

```python
# Check if ClamAV is running
sudo systemctl status clamav-daemon

# Update virus database
sudo freshclam
```

### Issue: "S3 upload failed: Access Denied"

**Cause**: IAM user doesn't have S3 permissions

**Fix**: Add S3 policy to IAM user:

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
      "Resource": "arn:aws:s3:::your-bucket-name/*"
    }
  ]
}
```

### Issue: "Cloudinary upload failed: Invalid credentials"

**Cause**: Wrong API key or secret

**Fix**: Check credentials in Cloudinary dashboard:
https://cloudinary.com/console/settings/security

---

## Advanced Features

### Responsive Images (Cloudinary)

```python
# Upload image
result = await upload_service.upload(file)

# Generate responsive URLs
base_url = result['url']

# Cloudinary transformations (automatic)
thumbnail = base_url.replace('/upload/', '/upload/w_200,h_200,c_fill/')
medium = base_url.replace('/upload/', '/upload/w_800,h_600,c_fit/')
large = base_url.replace('/upload/', '/upload/w_1920,h_1080,c_limit/')

# Frontend (srcset)
<img
  src="{base_url}"
  srcset="{thumbnail} 200w, {medium} 800w, {large} 1920w"
  sizes="(max-width: 600px) 200px, (max-width: 1200px) 800px, 1920px"
/>
```

### File Deduplication

```python
# Check if file already uploaded (by hash)
file_hash = hashlib.sha256(file_bytes).hexdigest()
existing_file = await db.files.find_one({'file_hash': file_hash})

if existing_file:
    # Return existing URL (don't re-upload)
    return existing_file['url']
else:
    # Upload new file
    result = await upload_service.upload(file)
    await db.files.insert_one({
        'file_hash': file_hash,
        'url': result['url'],
        'created_at': datetime.utcnow()
    })
```

### Direct Upload (Frontend → Cloudinary)

```javascript
// Get signed upload URL from backend
const response = await fetch('/upload/sign', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({filename: file.name})
});
const {signature, timestamp, upload_url} = await response.json();

// Upload directly to Cloudinary (doesn't touch backend)
const formData = new FormData();
formData.append('file', file);
formData.append('signature', signature);
formData.append('timestamp', timestamp);
formData.append('api_key', CLOUDINARY_API_KEY);

const uploadResponse = await fetch(upload_url, {
  method: 'POST',
  body: formData
});

const result = await uploadResponse.json();
console.log('Uploaded:', result.secure_url);
```

---

## Cost Optimization

### Cloudinary Free Tier

**Limits**:
- 25 credits/month (25GB bandwidth)
- 25GB storage
- Unlimited transformations

**Overage**:
- $0.0018 per additional credit

**Optimization**:
- Use Cloudinary for images/videos only
- Use S3 for documents (cheaper)
- Enable auto-format (WebP for browsers that support it)

### AWS S3 Costs

**Storage**: $0.023/GB/month (first 50TB)
**Transfer**: $0.09/GB (outbound to internet)

**Optimization**:
- Enable S3 Intelligent-Tiering (auto moves to cheaper tiers)
- Use CloudFront CDN (caching reduces transfer)
- Lifecycle policy (delete old files after 90 days)

**Example Cost**:
- 100GB storage = $2.30/month
- 500GB transfer = $45/month
- Total: ~$50/month

---

## Next Steps

1. **Read SKILL.md** → Complete production guide
2. **Review Security Tests** → tests/test_security.py (37 tests)
3. **Monitor Uploads** → Track success rate, malware detections
4. **Optimize Costs** → Enable Cloudinary auto-format, S3 lifecycle policies

---

## Support

- Cloudinary Docs: https://cloudinary.com/documentation
- AWS S3 Docs: https://docs.aws.amazon.com/s3/
- ClamAV Docs: https://docs.clamav.net/

**Security Issue?** → Review `tests/test_security.py` for validation examples
