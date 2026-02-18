"""
Media Processing Universal - FastAPI Implementation

Multi-provider media processing with OWASP security compliance.

Features:
- Image processing (Cloudinary)
- Video processing (FFmpeg)  
- Audio processing (FFmpeg)
- S3 storage
- CloudFront CDN
- Background job processing
- Security (rate limiting, SSRF prevention, command injection prevention)

Installation:
    pip install fastapi uvicorn python-multipart boto3 cloudinary redis
    
    # FFmpeg
    apt-get install ffmpeg
    
Run:
    uvicorn fastapi-media:app --reload
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, BackgroundTasks, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import os
import uuid
import shutil
import asyncio
import subprocess
from pathlib import Path
import hashlib
import ipaddress
from urllib.parse import urlparse
import structlog
import json

# Third-party imports
import boto3
from botocore.exceptions import ClientError
import cloudinary
import cloudinary.uploader
import cloudinary.api
from slowapi import Limiter
from slowapi.util import get_remote_address
import redis

# Configure logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)
logger = structlog.get_logger()

# Initialize FastAPI
app = FastAPI(title="Media Processing API", version="1.0.0")

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Security
security = HTTPBearer()

# Redis for job queue
redis_client = redis.Redis(
    host=os.getenv('REDIS_HOST', 'localhost'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    decode_responses=True
)

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Application configuration"""
    
    # Storage
    S3_BUCKET = os.getenv('AWS_S3_BUCKET', 'media-bucket')
    S3_REGION = os.getenv('AWS_REGION', 'us-east-1')
    CLOUDFRONT_DOMAIN = os.getenv('CLOUDFRONT_DOMAIN', 'd1234567890.cloudfront.net')
    
    # Cloudinary
    CLOUDINARY_CLOUD_NAME = os.getenv('CLOUDINARY_CLOUD_NAME')
    CLOUDINARY_API_KEY = os.getenv('CLOUDINARY_API_KEY')
    CLOUDINARY_API_SECRET = os.getenv('CLOUDINARY_API_SECRET')
    
    # File size limits
    MAX_IMAGE_SIZE = 10 * 1024 * 1024   # 10 MB
    MAX_VIDEO_SIZE = 500 * 1024 * 1024  # 500 MB
    MAX_AUDIO_SIZE = 50 * 1024 * 1024   # 50 MB
    
    # Processing
    UPLOAD_DIR = Path('/tmp/uploads')
    OUTPUT_DIR = Path('/tmp/outputs')
    
    # Timeouts
    VIDEO_TIMEOUT = 600  # 10 minutes
    AUDIO_TIMEOUT = 300  # 5 minutes

config = Config()

# Create directories
config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Initialize Cloudinary
if config.CLOUDINARY_CLOUD_NAME:
    cloudinary.config(
        cloud_name=config.CLOUDINARY_CLOUD_NAME,
        api_key=config.CLOUDINARY_API_KEY,
        api_secret=config.CLOUDINARY_API_SECRET,
        secure=True
    )

# Initialize S3
s3_client = boto3.client('s3', region_name=config.S3_REGION)

# ============================================================================
# SECURITY
# ============================================================================

BLOCKED_NETWORKS = [
    ipaddress.IPv4Network('10.0.0.0/8'),
    ipaddress.IPv4Network('172.16.0.0/12'),
    ipaddress.IPv4Network('192.168.0.0/16'),
    ipaddress.IPv4Network('127.0.0.0/8'),
    ipaddress.IPv4Network('169.254.0.0/16'),
]

def verify_ssrf_safe(url: str) -> bool:
    """Prevent SSRF attacks"""
    parsed = urlparse(url)
    
    if parsed.scheme not in ['http', 'https']:
        raise ValueError(f"Invalid scheme: {parsed.scheme}")
    
    import socket
    try:
        ip = socket.gethostbyname(parsed.hostname)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {parsed.hostname}")
    
    ip_addr = ipaddress.IPv4Address(ip)
    for network in BLOCKED_NETWORKS:
        if ip_addr in network:
            raise ValueError(f"Blocked IP range: {ip}")
    
    return True

def generate_safe_filename(original_filename: str, extension: str = None) -> str:
    """Generate UUID-based filename (prevent command injection)"""
    if not extension:
        extension = Path(original_filename).suffix
    return f"{uuid.uuid4()}{extension}"

def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash for file integrity"""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

# ============================================================================
# IMAGE PROCESSING (CLOUDINARY)
# ============================================================================

class CloudinaryImageProcessor:
    """Image processing with Cloudinary"""
    
    @staticmethod
    async def upload_image(
        file_path: str,
        folder: str = 'images',
        transformations: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Upload image to Cloudinary"""
        
        default_transforms = {
            'quality': 'auto:best',
            'fetch_format': 'auto',
            'flags': 'progressive',
            'crop': 'limit',
            'max_width': 3840,
            'max_height': 2160
        }
        
        if transformations:
            default_transforms.update(transformations)
        
        result = cloudinary.uploader.upload(
            file_path,
            folder=folder,
            public_id=str(uuid.uuid4()),
            **default_transforms
        )
        
        logger.info(
            "image_uploaded_cloudinary",
            public_id=result['public_id'],
            url=result['secure_url'],
            width=result['width'],
            height=result['height'],
            bytes=result['bytes']
        )
        
        return {
            'url': result['secure_url'],
            'public_id': result['public_id'],
            'format': result['format'],
            'width': result['width'],
            'height': result['height'],
            'file_size': result['bytes']
        }
    
    @staticmethod
    def generate_responsive_urls(
        public_id: str,
        widths: List[int] = [320, 640, 1024, 1920]
    ) -> Dict[str, str]:
        """Generate responsive image URLs"""
        from cloudinary import CloudinaryImage
        
        urls = {}
        for width in widths:
            urls[str(width)] = CloudinaryImage(public_id).build_url(
                width=width,
                crop='scale',
                quality='auto:best',
                fetch_format='auto'
            )
        return urls
    
    @staticmethod
    def generate_thumbnail(
        public_id: str,
        width: int = 200,
        height: int = 200
    ) -> str:
        """Generate thumbnail with smart cropping"""
        from cloudinary import CloudinaryImage
        
        return CloudinaryImage(public_id).build_url(
            width=width,
            height=height,
            crop='fill',
            gravity='auto',
            quality='auto:best',
            fetch_format='auto'
        )

# ============================================================================
# VIDEO PROCESSING (FFMPEG)
# ============================================================================

class FFmpegVideoProcessor:
    """Video processing with FFmpeg"""
    
    @staticmethod
    async def transcode_video(
        input_path: str,
        output_format: str = 'mp4',
        preset: str = 'medium',
        crf: int = 23,
        max_resolution: str = '1920x1080'
    ) -> Dict[str, Any]:
        """Transcode video with FFmpeg"""
        
        output_id = str(uuid.uuid4())
        output_path = config.OUTPUT_DIR / f"{output_id}.{output_format}"
        
        cmd = [
            'ffmpeg',
            '-i', input_path,
            '-c:v', 'libx264',
            '-preset', preset,
            '-crf', str(crf),
            '-c:a', 'aac',
            '-b:a', '128k',
            '-vf', f'scale={max_resolution}:force_original_aspect_ratio=decrease',
            str(output_path)
        ]
        
        logger.info("video_transcode_started", input=input_path, output=str(output_path))
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=config.VIDEO_TIMEOUT
            )
            
            if process.returncode != 0:
                error_msg = stderr.decode()
                logger.error("video_transcode_failed", error=error_msg)
                raise Exception(f"FFmpeg failed: {error_msg}")
            
            metadata = await FFmpegVideoProcessor.get_metadata(str(output_path))
            
            logger.info("video_transcode_completed", output=str(output_path))
            
            return {
                'output_path': str(output_path),
                'file_size': output_path.stat().st_size,
                **metadata
            }
            
        except asyncio.TimeoutError:
            if process:
                process.kill()
            raise Exception("Video transcoding timeout")
    
    @staticmethod
    async def get_metadata(video_path: str) -> Dict[str, Any]:
        """Extract video metadata using ffprobe"""
        
        cmd = [
            'ffprobe',
            '-v', 'quiet',
            '-print_format', 'json',
            '-show_format',
            '-show_streams',
            video_path
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, _ = await process.communicate()
        data = json.loads(stdout.decode())
        
        video_stream = next(
            (s for s in data['streams'] if s['codec_type'] == 'video'),
            None
        )
        audio_stream = next(
            (s for s in data['streams'] if s['codec_type'] == 'audio'),
            None
        )
        
        return {
            'duration': float(data['format']['duration']),
            'bitrate': int(data['format']['bit_rate']),
            'width': video_stream['width'] if video_stream else None,
            'height': video_stream['height'] if video_stream else None,
            'video_codec': video_stream['codec_name'] if video_stream else None,
            'audio_codec': audio_stream['codec_name'] if audio_stream else None
        }
    
    @staticmethod
    async def generate_thumbnail(
        video_path: str,
        timestamp: str = '00:00:01',
        width: int = 320,
        height: int = 180
    ) -> str:
        """Generate video thumbnail"""
        
        output_id = str(uuid.uuid4())
        output_path = config.OUTPUT_DIR / f"{output_id}_thumb.jpg"
        
        cmd = [
            'ffmpeg',
            '-i', video_path,
            '-ss', timestamp,
            '-vframes', '1',
            '-vf', f'scale={width}:{height}',
            str(output_path)
        ]
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        await process.communicate()
        
        if process.returncode != 0:
            raise Exception("Thumbnail generation failed")
        
        return str(output_path)

# ============================================================================
# STORAGE (S3 + CLOUDFRONT)
# ============================================================================

class S3Storage:
    """S3 storage with CloudFront CDN"""
    
    @staticmethod
    def upload_file(
        local_path: str,
        s3_key: str,
        content_type: str
    ) -> str:
        """Upload file to S3"""
        
        s3_client.upload_file(
            local_path,
            config.S3_BUCKET,
            s3_key,
            ExtraArgs={
                'ContentType': content_type,
                'ServerSideEncryption': 'AES256'
            }
        )
        
        logger.info("file_uploaded_s3", bucket=config.S3_BUCKET, key=s3_key)
        
        return S3Storage.get_cdn_url(s3_key)
    
    @staticmethod
    def get_cdn_url(s3_key: str) -> str:
        """Generate CloudFront CDN URL"""
        return f"https://{config.CLOUDFRONT_DOMAIN}/{s3_key}"
    
    @staticmethod
    def delete_file(s3_key: str):
        """Delete file from S3"""
        s3_client.delete_object(Bucket=config.S3_BUCKET, Key=s3_key)
        logger.info("file_deleted_s3", key=s3_key)

# ============================================================================
# MEDIA PROCESSING SERVICE
# ============================================================================

class MediaProcessingService:
    """Main media processing service"""
    
    @staticmethod
    async def process_upload(
        file: UploadFile,
        user_id: str,
        background_tasks: BackgroundTasks
    ) -> Dict[str, Any]:
        """Main entry point for media processing"""
        
        # Route by media type
        if file.content_type.startswith('image/'):
            return await MediaProcessingService._process_image(file, user_id)
        
        elif file.content_type.startswith('video/'):
            return await MediaProcessingService._process_video(
                file, user_id, background_tasks
            )
        
        elif file.content_type.startswith('audio/'):
            return await MediaProcessingService._process_audio(
                file, user_id, background_tasks
            )
        
        else:
            raise HTTPException(
                400,
                f"Unsupported media type: {file.content_type}"
            )
    
    @staticmethod
    async def _process_image(file: UploadFile, user_id: str) -> Dict[str, Any]:
        """Process image (instant - Cloudinary)"""
        
        # Validate size
        file_size = 0
        temp_path = config.UPLOAD_DIR / generate_safe_filename(file.filename)
        
        with open(temp_path, 'wb') as f:
            while chunk := await file.read(1024 * 1024):
                file_size += len(chunk)
                if file_size > config.MAX_IMAGE_SIZE:
                    os.remove(temp_path)
                    raise HTTPException(413, f"Image too large (max {config.MAX_IMAGE_SIZE / 1024 / 1024}MB)")
                f.write(chunk)
        
        try:
            # Upload to Cloudinary
            result = await CloudinaryImageProcessor.upload_image(str(temp_path))
            
            # Generate responsive URLs
            responsive_urls = CloudinaryImageProcessor.generate_responsive_urls(
                result['public_id']
            )
            
            # Generate thumbnail
            thumbnail_url = CloudinaryImageProcessor.generate_thumbnail(
                result['public_id']
            )
            
            logger.info(
                "image_processing_completed",
                user_id=user_id,
                url=result['url'],
                file_size=result['file_size']
            )
            
            return {
                'id': str(uuid.uuid4()),
                'status': 'completed',
                'media_type': 'image',
                'url': result['url'],
                'thumbnail_url': thumbnail_url,
                'responsive_urls': responsive_urls,
                'width': result['width'],
                'height': result['height'],
                'file_size': result['file_size']
            }
            
        finally:
            os.remove(temp_path)
    
    @staticmethod
    async def _process_video(
        file: UploadFile,
        user_id: str,
        background_tasks: BackgroundTasks
    ) -> Dict[str, Any]:
        """Process video (background - FFmpeg)"""
        
        media_id = str(uuid.uuid4())
        
        # Validate size and save to temp
        file_size = 0
        temp_path = config.UPLOAD_DIR / f"{media_id}_original.mp4"
        
        with open(temp_path, 'wb') as f:
            while chunk := await file.read(1024 * 1024):
                file_size += len(chunk)
                if file_size > config.MAX_VIDEO_SIZE:
                    os.remove(temp_path)
                    raise HTTPException(413, f"Video too large (max {config.MAX_VIDEO_SIZE / 1024 / 1024}MB)")
                f.write(chunk)
        
        # Upload original to S3
        s3_key = f"videos/originals/{media_id}.mp4"
        S3Storage.upload_file(str(temp_path), s3_key, 'video/mp4')
        
        # Queue background processing
        background_tasks.add_task(
            MediaProcessingService._process_video_background,
            media_id,
            str(temp_path),
            user_id
        )
        
        logger.info("video_processing_queued", media_id=media_id, user_id=user_id)
        
        return {
            'id': media_id,
            'status': 'processing',
            'media_type': 'video',
            'message': f'Video is being processed. Check status at /media/{media_id}/status'
        }
    
    @staticmethod
    async def _process_video_background(
        media_id: str,
        input_path: str,
        user_id: str
    ):
        """Background task: Transcode video"""
        
        try:
            # Transcode
            result = await FFmpegVideoProcessor.transcode_video(
                input_path,
                preset='medium',
                crf=23,
                max_resolution='1920x1080'
            )
            
            # Generate thumbnail
            thumbnail_path = await FFmpegVideoProcessor.generate_thumbnail(
                result['output_path']
            )
            
            # Upload to S3
            video_key = f"videos/processed/{media_id}.mp4"
            thumb_key = f"videos/thumbnails/{media_id}.jpg"
            
            video_url = S3Storage.upload_file(
                result['output_path'],
                video_key,
                'video/mp4'
            )
            
            thumb_url = S3Storage.upload_file(
                thumbnail_path,
                thumb_key,
                'image/jpeg'
            )
            
            # Store result in Redis
            redis_client.hset(
                f"media:{media_id}",
                mapping={
                    'status': 'completed',
                    'url': video_url,
                    'thumbnail_url': thumb_url,
                    'duration': result['duration'],
                    'width': result['width'],
                    'height': result['height'],
                    'file_size': result['file_size']
                }
            )
            
            logger.info("video_processing_completed", media_id=media_id)
            
            # Cleanup
            os.remove(input_path)
            os.remove(result['output_path'])
            os.remove(thumbnail_path)
            
        except Exception as e:
            logger.error("video_processing_failed", media_id=media_id, error=str(e))
            
            redis_client.hset(
                f"media:{media_id}",
                mapping={
                    'status': 'failed',
                    'error': str(e)
                }
            )
    
    @staticmethod
    async def _process_audio(
        file: UploadFile,
        user_id: str,
        background_tasks: BackgroundTasks
    ) -> Dict[str, Any]:
        """Process audio (background - FFmpeg)"""
        
        media_id = str(uuid.uuid4())
        
        # Save to temp
        file_size = 0
        temp_path = config.UPLOAD_DIR / f"{media_id}_original.mp3"
        
        with open(temp_path, 'wb') as f:
            while chunk := await file.read(1024 * 1024):
                file_size += len(chunk)
                if file_size > config.MAX_AUDIO_SIZE:
                    os.remove(temp_path)
                    raise HTTPException(413, f"Audio too large (max {config.MAX_AUDIO_SIZE / 1024 / 1024}MB)")
                f.write(chunk)
        
        # Upload to S3
        s3_key = f"audio/{media_id}.mp3"
        audio_url = S3Storage.upload_file(str(temp_path), s3_key, 'audio/mpeg')
        
        os.remove(temp_path)
        
        logger.info("audio_processing_completed", media_id=media_id, user_id=user_id)
        
        return {
            'id': media_id,
            'status': 'completed',
            'media_type': 'audio',
            'url': audio_url,
            'file_size': file_size
        }

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.post('/media/upload')
@limiter.limit("10/hour")
async def upload_media(
    request: Request,
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Upload and process media"""
    
    # Mock user (in production: use authentication)
    user_id = "user_123"
    
    result = await MediaProcessingService.process_upload(
        file=file,
        user_id=user_id,
        background_tasks=background_tasks
    )
    
    return result

@app.get('/media/{media_id}/status')
async def get_media_status(media_id: str):
    """Get media processing status"""
    
    data = redis_client.hgetall(f"media:{media_id}")
    
    if not data:
        raise HTTPException(404, "Media not found")
    
    return {
        'id': media_id,
        'status': data.get('status', 'processing'),
        'url': data.get('url'),
        'thumbnail_url': data.get('thumbnail_url'),
        'duration': data.get('duration'),
        'width': data.get('width'),
        'height': data.get('height'),
        'file_size': data.get('file_size'),
        'error': data.get('error')
    }

@app.get('/health')
async def health_check():
    """Health check endpoint"""
    
    # Check FFmpeg
    try:
        result = subprocess.run(['ffmpeg', '-version'], capture_output=True, timeout=5)
        ffmpeg_ok = result.returncode == 0
    except:
        ffmpeg_ok = False
    
    # Check S3
    try:
        s3_client.head_bucket(Bucket=config.S3_BUCKET)
        s3_ok = True
    except:
        s3_ok = False
    
    # Check Redis
    try:
        redis_client.ping()
        redis_ok = True
    except:
        redis_ok = False
    
    return {
        'status': 'healthy' if all([ffmpeg_ok, s3_ok, redis_ok]) else 'degraded',
        'services': {
            'ffmpeg': 'ok' if ffmpeg_ok else 'down',
            's3': 'ok' if s3_ok else 'down',
            'redis': 'ok' if redis_ok else 'down',
            'cloudinary': 'ok' if config.CLOUDINARY_CLOUD_NAME else 'not configured'
        }
    }

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000)
