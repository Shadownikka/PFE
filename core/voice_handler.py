#!/usr/bin/env python3
"""
NetMind Voice Handler — Backend speech-to-text transcription
Primary: Browser Web Speech API (no backend needed)
Fallback: SpeechRecognition library (Google Web Speech API)
"""

import io
import os
import tempfile
import time
from termcolor import colored


def transcribe_audio_bytes(audio_data: bytes, content_type: str = "audio/webm") -> str:
    """
    Transcribe audio bytes to text using SpeechRecognition.
    Called when browser sends a recorded audio blob to the backend.

    Args:
        audio_data: Raw audio bytes (webm, wav, ogg)
        content_type: MIME type of the audio

    Returns:
        Transcribed text string, or empty string on failure
    """
    try:
        import speech_recognition as sr
    except ImportError:
        return _whisper_fallback(audio_data, content_type)

    recognizer = sr.Recognizer()

    # Write to temp file for SpeechRecognition to load
    suffix = ".webm"
    if "wav" in content_type:
        suffix = ".wav"
    elif "ogg" in content_type:
        suffix = ".ogg"
    elif "mp4" in content_type or "m4a" in content_type:
        suffix = ".mp4"

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(audio_data)
        tmp_path = tmp.name

    try:
        # Convert non-wav formats via ffmpeg if available
        wav_path = tmp_path
        if suffix != ".wav":
            wav_path = tmp_path.replace(suffix, ".wav")
            ret = os.system(f'ffmpeg -y -i "{tmp_path}" -ar 16000 -ac 1 "{wav_path}" 2>/dev/null')
            if ret != 0:
                # ffmpeg not available — try anyway
                wav_path = tmp_path

        with sr.AudioFile(wav_path) as source:
            audio = recognizer.record(source)

        text = recognizer.recognize_google(audio)
        print(colored(f"[Voice] Transcribed: '{text}'", "green"))
        return text

    except sr.UnknownValueError:
        print(colored("[Voice] Could not understand audio", "yellow"))
        return ""
    except sr.RequestError as e:
        print(colored(f"[Voice] Google Speech API error: {e}", "red"))
        return _whisper_fallback(audio_data, content_type)
    except Exception as e:
        print(colored(f"[Voice] Transcription error: {e}", "red"))
        return ""
    finally:
        # Cleanup temp files
        for path in [tmp_path, wav_path if wav_path != tmp_path else None]:
            if path and os.path.exists(path):
                try:
                    os.unlink(path)
                except Exception:
                    pass


def _whisper_fallback(audio_data: bytes, content_type: str) -> str:
    """
    Attempt transcription using local OpenAI Whisper if available.
    Only used if SpeechRecognition or Google API fails.
    """
    try:
        import whisper
        import numpy as np
        import soundfile as sf

        print(colored("[Voice] Trying local Whisper fallback...", "cyan"))

        model = whisper.load_model("base")

        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
            tmp.write(audio_data)
            tmp_path = tmp.name

        result = model.transcribe(tmp_path, language="en")
        text = result.get("text", "").strip()

        os.unlink(tmp_path)
        print(colored(f"[Voice] Whisper transcribed: '{text}'", "green"))
        return text

    except ImportError:
        return ""
    except Exception as e:
        print(colored(f"[Voice] Whisper failed: {e}", "red"))
        return ""


def transcribe_from_mic(duration: int = 8) -> str:
    """
    Capture audio from the system microphone and transcribe it.
    Used for CLI-based onboarding (not the web interface).

    Args:
        duration: How many seconds to record

    Returns:
        Transcribed text
    """
    try:
        import speech_recognition as sr
    except ImportError:
        print(colored("[Voice] 'speech_recognition' not installed. Run: pip install SpeechRecognition pyaudio", "red"))
        return ""

    recognizer = sr.Recognizer()

    try:
        with sr.Microphone() as source:
            print(colored(f"[Voice] 🎤 Recording for {duration} seconds... speak now!", "cyan"))
            recognizer.adjust_for_ambient_noise(source, duration=0.5)
            audio = recognizer.listen(source, timeout=duration, phrase_time_limit=duration)

        print(colored("[Voice] Processing...", "cyan"))
        text = recognizer.recognize_google(audio)
        print(colored(f"[Voice] You said: '{text}'", "green"))
        return text

    except sr.WaitTimeoutError:
        print(colored("[Voice] No speech detected", "yellow"))
        return ""
    except sr.UnknownValueError:
        print(colored("[Voice] Could not understand speech", "yellow"))
        return ""
    except sr.RequestError as e:
        print(colored(f"[Voice] Speech API error: {e}", "red"))
        return ""
    except Exception as e:
        print(colored(f"[Voice] Microphone error: {e}", "red"))
        return ""


def is_speech_recognition_available() -> bool:
    """Check if the speech_recognition library is installed."""
    try:
        import speech_recognition
        return True
    except ImportError:
        return False


def is_whisper_available() -> bool:
    """Check if local Whisper model is available."""
    try:
        import whisper
        return True
    except ImportError:
        return False
