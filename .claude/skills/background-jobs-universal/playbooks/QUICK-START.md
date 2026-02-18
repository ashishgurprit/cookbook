# Background Jobs Universal - Quick Start (15 min)

## Setup

```bash
# Install Redis
brew install redis
brew services start redis

# Install Celery
pip install celery redis

# Install Bull (Node.js)
npm install bull
```

## Celery Usage

```python
# tasks.py
from celery import Celery

app = Celery('tasks', broker='redis://localhost:6379/0')

@app.task(bind=True, max_retries=3)
def process_video(self, video_id):
    try:
        # Heavy processing
        transcode_video(video_id)
    except Exception as exc:
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=60)

# main.py
process_video.delay('video-123')

# Run worker
celery -A tasks worker --loglevel=info
```

## Cost

- Redis: $150/month
- Infrastructure: $50/month
- **Total**: $200/month (1M jobs)
