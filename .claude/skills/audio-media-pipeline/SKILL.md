---
name: audio-media-pipeline
description: "End-to-end audio/media processing pipeline — transcription, preprocessing, voice cloning, subtitle generation, and speech translation. Use when: (1) Transcribing audio/video with Whisper, (2) Preprocessing audio files, (3) Cloning voices for TTS, (4) Generating SRT/VTT subtitles, (5) Translating and dubbing speech."
consumes_modules:
  - whisper-transcribe
  - audio-preprocessor
  - voice-clone
  - subtitle-sync
  - speech-translate
---

# Audio Media Pipeline

> End-to-end audio/media processing pipeline — transcription, preprocessing, voice cloning, subtitle generation, and speech translation. Use when: transcribing audio with Whisper, normalizing/cleaning audio, cloning voices for synthesis, generating synchronized subtitles, or building multi-language dubbing pipelines.

---

## Module Dependencies

| Module | What It Provides |
|--------|-----------------|
| `whisper-transcribe` | OpenAI Whisper integration, batch transcription, word-level timestamps, language detection |
| `audio-preprocessor` | Audio normalization, noise reduction, silence trimming, format conversion, channel mixing |
| `voice-clone` | Voice profile extraction, TTS with cloned voice, speaker embedding, voice similarity scoring |
| `subtitle-sync` | SRT/VTT generation, timestamp alignment, subtitle splitting, forced alignment |
| `speech-translate` | Speech-to-speech translation, text translation bridge, language detection, multi-language output |

---

## Overview

This skill covers the complete audio/media processing stack from raw input to translated, subtitled output. The 5 modules form a natural pipeline:

```
Raw Audio → [audio-preprocessor] → Clean Audio
Clean Audio → [whisper-transcribe] → Transcript + Timestamps
Transcript → [subtitle-sync] → SRT/VTT Subtitles
Transcript → [speech-translate] → Translated Text
Translated Text → [voice-clone] → Dubbed Audio in Target Language
```

All examples use Python with async patterns suitable for production workloads.

---

## 1. Audio Preprocessing

Always preprocess audio before transcription to maximize accuracy.

### Normalization and Noise Reduction

```python
from audio_preprocessor import (
    AudioNormalizer,
    NoiseReducer,
    SilenceTrimmer,
    FormatConverter,
    AudioPipeline,
)

# Build a preprocessing pipeline
pipeline = AudioPipeline(steps=[
    FormatConverter(target_format="wav", sample_rate=16000, channels=1),
    SilenceTrimmer(
        silence_threshold_db=-40,
        min_silence_duration_ms=500,
        padding_ms=100,
    ),
    NoiseReducer(
        method="spectral_gating",
        noise_profile="auto",        # auto-detect noise from first 0.5s
        reduction_strength=0.7,
    ),
    AudioNormalizer(
        target_lufs=-16.0,           # broadcast standard loudness
        peak_limit_db=-1.0,
    ),
])

# Process a single file
clean_audio = await pipeline.process("raw_interview.mp3")
clean_audio.save("clean_interview.wav")

# Batch process a directory
results = await pipeline.process_batch(
    input_dir="raw_audio/",
    output_dir="clean_audio/",
    concurrency=4,
)
print(f"Processed {len(results)} files, {sum(r.ok for r in results)} succeeded")
```

### Audio Segmentation for Long Files

```python
from audio_preprocessor import AudioSegmenter

segmenter = AudioSegmenter(
    max_segment_duration_s=300,    # 5-minute segments
    split_on_silence=True,
    min_silence_duration_ms=700,
    overlap_s=2,                   # 2s overlap between segments
)

segments = segmenter.segment("long_podcast.wav")
# Returns: [AudioSegment(start=0, end=298), AudioSegment(start=296, end=594), ...]

for seg in segments:
    print(f"Segment {seg.index}: {seg.start_s:.1f}s - {seg.end_s:.1f}s ({seg.duration_s:.1f}s)")
```

---

## 2. Whisper Transcription

### Basic Transcription with Timestamps

```python
from whisper_transcribe import (
    WhisperTranscriber,
    TranscriptionConfig,
    WordTimestamp,
)

transcriber = WhisperTranscriber(
    model="large-v3",
    device="cuda",                  # or "cpu", "mps"
    compute_type="float16",
)

config = TranscriptionConfig(
    language=None,                  # auto-detect
    word_timestamps=True,
    vad_filter=True,                # voice activity detection
    initial_prompt="This is a tech podcast about AI and software engineering.",
)

result = await transcriber.transcribe("clean_interview.wav", config=config)

print(f"Language: {result.language} (confidence: {result.language_confidence:.2f})")
print(f"Duration: {result.duration_s:.1f}s")
print(f"Segments: {len(result.segments)}")

for segment in result.segments:
    print(f"[{segment.start:.2f} - {segment.end:.2f}] {segment.text}")
    # Word-level timestamps
    for word in segment.words:
        print(f"  {word.start:.2f}s: '{word.text}' (conf: {word.confidence:.2f})")
```

### Batch Transcription Pipeline

```python
from whisper_transcribe import BatchTranscriber

batch = BatchTranscriber(
    model="large-v3",
    device="cuda",
    max_concurrent=2,
    output_formats=["json", "srt", "txt"],
)

results = await batch.transcribe_directory(
    input_dir="clean_audio/",
    output_dir="transcripts/",
    config=config,
    on_progress=lambda done, total: print(f"Progress: {done}/{total}"),
)

# Per-file results
for r in results:
    print(f"{r.filename}: {r.status}, {r.duration_s:.0f}s, lang={r.language}")
```

### Speaker Diarization

```python
from whisper_transcribe import WhisperTranscriber, DiarizationConfig

transcriber = WhisperTranscriber(model="large-v3")

diarization = DiarizationConfig(
    enabled=True,
    min_speakers=2,
    max_speakers=5,
    model="pyannote/speaker-diarization-3.1",
)

result = await transcriber.transcribe(
    "panel_discussion.wav",
    config=TranscriptionConfig(word_timestamps=True),
    diarization=diarization,
)

for segment in result.segments:
    print(f"[Speaker {segment.speaker}] {segment.start:.1f}s: {segment.text}")
```

---

## 3. Subtitle Generation

### SRT and VTT Generation

```python
from subtitle_sync import (
    SubtitleGenerator,
    SubtitleFormat,
    SubtitleStyle,
)

generator = SubtitleGenerator(
    max_chars_per_line=42,
    max_lines=2,
    min_duration_ms=1000,
    max_duration_ms=7000,
    gap_between_ms=100,
)

# Generate from transcription result
srt_content = generator.generate(
    segments=result.segments,
    format=SubtitleFormat.SRT,
)

vtt_content = generator.generate(
    segments=result.segments,
    format=SubtitleFormat.VTT,
    style=SubtitleStyle(
        font_size="medium",
        position="bottom",
        background_opacity=0.75,
    ),
)

# Write to files
with open("output.srt", "w", encoding="utf-8") as f:
    f.write(srt_content)

with open("output.vtt", "w", encoding="utf-8") as f:
    f.write(vtt_content)
```

### Forced Alignment for Better Sync

```python
from subtitle_sync import ForcedAligner

aligner = ForcedAligner(
    model="wav2vec2",
    language="en",
)

# Align existing transcript text to audio for precise timestamps
aligned = await aligner.align(
    audio_path="clean_interview.wav",
    transcript_text=existing_transcript,
)

# Result has word-level timestamps even if original transcript had none
for word in aligned.words:
    print(f"{word.start:.3f} - {word.end:.3f}: {word.text}")

# Generate subtitles from aligned output
subtitles = generator.generate(
    segments=aligned.to_segments(),
    format=SubtitleFormat.SRT,
)
```

### Subtitle Translation

```python
from subtitle_sync import SubtitleTranslator
from speech_translate import TextTranslator

translator = TextTranslator(model="nllb-200-3.3B")

sub_translator = SubtitleTranslator(
    translator=translator,
    preserve_timing=True,
    adjust_duration_for_language=True,  # some languages need more reading time
)

translated_srt = await sub_translator.translate(
    subtitle_path="output.srt",
    source_language="en",
    target_language="es",
)
translated_srt.save("output_es.srt")
```

---

## 4. Speech Translation

### Text Translation Bridge

```python
from speech_translate import (
    TextTranslator,
    SpeechTranslator,
    LanguageDetector,
)

# Detect language first
detector = LanguageDetector()
detected = detector.detect("This is a sample sentence.")
print(f"Detected: {detected.language} (confidence: {detected.confidence:.2f})")

# Translate text
translator = TextTranslator(model="nllb-200-3.3B")

translated = await translator.translate(
    text="Welcome to our platform. Let me show you around.",
    source_lang="en",
    target_lang="ja",
)
print(f"Translation: {translated.text}")
print(f"Score: {translated.confidence:.2f}")
```

### Full Speech-to-Speech Translation

```python
from speech_translate import SpeechTranslator

s2s = SpeechTranslator(
    transcription_model="large-v3",     # Whisper model
    translation_model="nllb-200-3.3B",
    tts_model="xtts-v2",
)

result = await s2s.translate(
    audio_path="english_narration.wav",
    source_lang="en",
    target_lang="fr",
    preserve_voice=True,    # clone original speaker's voice
    output_path="french_narration.wav",
)

print(f"Source: {result.source_text}")
print(f"Translation: {result.translated_text}")
print(f"Audio saved to: {result.output_path}")
```

### Multi-Language Dubbing Pipeline

```python
from speech_translate import DubbingPipeline

pipeline = DubbingPipeline(
    transcriber_model="large-v3",
    translator_model="nllb-200-3.3B",
    tts_model="xtts-v2",
)

target_languages = ["es", "fr", "de", "ja", "pt"]

results = await pipeline.dub(
    audio_path="english_tutorial.wav",
    source_lang="en",
    target_langs=target_languages,
    output_dir="dubbed/",
    generate_subtitles=True,
    subtitle_format="srt",
    on_progress=lambda lang, step: print(f"[{lang}] {step}"),
)

for lang, result in results.items():
    print(f"{lang}: audio={result.audio_path}, subs={result.subtitle_path}")
```

---

## 5. Voice Cloning

### Extract Voice Profile

```python
from voice_clone import (
    VoiceProfileExtractor,
    VoiceSynthesizer,
    SimilarityScorer,
)

extractor = VoiceProfileExtractor(model="xtts-v2")

# Extract speaker embedding from reference audio (10-30s recommended)
profile = await extractor.extract(
    audio_path="speaker_reference.wav",
    trim_silence=True,
    min_duration_s=10,
)

print(f"Profile ID: {profile.id}")
print(f"Duration used: {profile.duration_s:.1f}s")
print(f"Quality score: {profile.quality_score:.2f}")

# Save for reuse
profile.save("profiles/narrator.json")
```

### Synthesize Speech with Cloned Voice

```python
from voice_clone import VoiceSynthesizer, VoiceProfile

synthesizer = VoiceSynthesizer(model="xtts-v2", device="cuda")
profile = VoiceProfile.load("profiles/narrator.json")

# Generate speech in the cloned voice
audio = await synthesizer.synthesize(
    text="Welcome back to our channel. Today we are exploring new features.",
    voice_profile=profile,
    language="en",
    speed=1.0,
    output_format="wav",
)
audio.save("synthesized_intro.wav")

# Score similarity to original
scorer = SimilarityScorer()
similarity = scorer.compare(
    reference="speaker_reference.wav",
    generated="synthesized_intro.wav",
)
print(f"Voice similarity: {similarity.score:.2f} ({similarity.rating})")
```

### Voice Cloning for Dubbing

```python
from voice_clone import VoiceProfileExtractor, VoiceSynthesizer
from speech_translate import TextTranslator

extractor = VoiceProfileExtractor(model="xtts-v2")
synthesizer = VoiceSynthesizer(model="xtts-v2")
translator = TextTranslator(model="nllb-200-3.3B")

async def dub_with_original_voice(
    audio_path: str,
    transcript: str,
    target_lang: str,
) -> str:
    # 1. Extract speaker voice
    profile = await extractor.extract(audio_path)

    # 2. Translate transcript
    translated = await translator.translate(
        text=transcript,
        source_lang="en",
        target_lang=target_lang,
    )

    # 3. Synthesize in original voice, target language
    dubbed = await synthesizer.synthesize(
        text=translated.text,
        voice_profile=profile,
        language=target_lang,
    )

    output_path = f"dubbed_{target_lang}.wav"
    dubbed.save(output_path)
    return output_path
```

---

## 6. Full Pipeline Example

### End-to-End: Raw Audio to Multi-Language Subtitled Video

```python
from audio_preprocessor import AudioPipeline, FormatConverter, NoiseReducer, AudioNormalizer
from whisper_transcribe import WhisperTranscriber, TranscriptionConfig
from subtitle_sync import SubtitleGenerator, SubtitleFormat
from speech_translate import TextTranslator
from subtitle_sync import SubtitleTranslator

async def process_video_audio(input_audio: str, target_langs: list[str]):
    # Step 1: Preprocess
    pipeline = AudioPipeline(steps=[
        FormatConverter(target_format="wav", sample_rate=16000, channels=1),
        NoiseReducer(method="spectral_gating"),
        AudioNormalizer(target_lufs=-16.0),
    ])
    clean = await pipeline.process(input_audio)

    # Step 2: Transcribe
    transcriber = WhisperTranscriber(model="large-v3")
    transcript = await transcriber.transcribe(
        clean.path,
        config=TranscriptionConfig(word_timestamps=True, vad_filter=True),
    )

    # Step 3: Generate base subtitles
    generator = SubtitleGenerator(max_chars_per_line=42, max_lines=2)
    base_srt = generator.generate(transcript.segments, SubtitleFormat.SRT)

    with open("subtitles/en.srt", "w") as f:
        f.write(base_srt)

    # Step 4: Translate subtitles to each target language
    translator = TextTranslator(model="nllb-200-3.3B")
    sub_translator = SubtitleTranslator(translator=translator, preserve_timing=True)

    for lang in target_langs:
        translated = await sub_translator.translate(
            subtitle_content=base_srt,
            source_language="en",
            target_language=lang,
        )
        translated.save(f"subtitles/{lang}.srt")
        print(f"Generated subtitles for: {lang}")

    return {
        "transcript": transcript,
        "base_subtitles": "subtitles/en.srt",
        "translated_subtitles": {
            lang: f"subtitles/{lang}.srt" for lang in target_langs
        },
    }

# Usage
result = await process_video_audio(
    "raw_lecture.mp3",
    target_langs=["es", "fr", "de", "ja"],
)
```

---

## Quick Reference

| Task | Module | Key API |
|------|--------|---------|
| Normalize audio loudness | `audio-preprocessor` | `AudioNormalizer(target_lufs)` |
| Remove background noise | `audio-preprocessor` | `NoiseReducer(method)` |
| Trim silence | `audio-preprocessor` | `SilenceTrimmer(threshold_db)` |
| Convert audio format | `audio-preprocessor` | `FormatConverter(format, sample_rate)` |
| Split long audio | `audio-preprocessor` | `AudioSegmenter(max_duration_s)` |
| Transcribe audio | `whisper-transcribe` | `WhisperTranscriber.transcribe(path)` |
| Batch transcribe | `whisper-transcribe` | `BatchTranscriber.transcribe_directory()` |
| Speaker diarization | `whisper-transcribe` | `DiarizationConfig(enabled=True)` |
| Generate SRT/VTT | `subtitle-sync` | `SubtitleGenerator.generate(segments)` |
| Force-align transcript | `subtitle-sync` | `ForcedAligner.align(audio, text)` |
| Translate subtitles | `subtitle-sync` | `SubtitleTranslator.translate(srt, lang)` |
| Detect language | `speech-translate` | `LanguageDetector.detect(text)` |
| Translate text | `speech-translate` | `TextTranslator.translate(text, lang)` |
| Speech-to-speech translate | `speech-translate` | `SpeechTranslator.translate(audio, lang)` |
| Multi-language dubbing | `speech-translate` | `DubbingPipeline.dub(audio, langs)` |
| Extract voice profile | `voice-clone` | `VoiceProfileExtractor.extract(audio)` |
| Synthesize cloned voice | `voice-clone` | `VoiceSynthesizer.synthesize(text, profile)` |
| Compare voice similarity | `voice-clone` | `SimilarityScorer.compare(ref, gen)` |

### Pipeline Decision Tree

```
What do you need to do with audio/media?
├── Transcribe speech → whisper-transcribe
│   ├── Single file → WhisperTranscriber.transcribe()
│   ├── Many files → BatchTranscriber.transcribe_directory()
│   └── Identify speakers → DiarizationConfig
├── Clean up audio first → audio-preprocessor
│   ├── Background noise → NoiseReducer
│   ├── Volume issues → AudioNormalizer
│   └── Long recording → AudioSegmenter
├── Generate subtitles → subtitle-sync
│   ├── From Whisper output → SubtitleGenerator.generate()
│   ├── From existing text → ForcedAligner.align()
│   └── Translate existing subs → SubtitleTranslator
├── Translate speech → speech-translate
│   ├── Text only → TextTranslator
│   ├── Audio to audio → SpeechTranslator
│   └── Multiple languages → DubbingPipeline
└── Clone a voice → voice-clone
    ├── Extract profile → VoiceProfileExtractor
    ├── Generate speech → VoiceSynthesizer
    └── Verify quality → SimilarityScorer
```
