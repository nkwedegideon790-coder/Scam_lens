import io

import pytest
from PIL import Image, ImageDraw, ImageFont

from backend import ocr
from backend.errors import InvalidImageError, NoTextFoundError

needs_tesseract = pytest.mark.skipif(not ocr.is_available(), reason="tesseract binary not installed")


def _font(size):
    for path in ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "DejaVuSans.ttf"):
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


def png(text=None, size=(1080, 500), bg="white", fg="black", font_size=44):
    img = Image.new("RGB", size, bg)
    if text:
        d = ImageDraw.Draw(img)
        y = 40
        for line in text.split("\n"):
            d.text((40, y), line, fill=fg, font=_font(font_size))
            y += font_size + 20
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


@needs_tesseract
def test_reads_clean_screenshot_text():
    out = ocr.extract_text(png("Your account will be blocked\nReply with your OTP now"))
    assert "account" in out.text.lower() and "otp" in out.text.lower()


@needs_tesseract
def test_reads_dark_mode_screenshot():
    out = ocr.extract_text(png("Verify your account today\nClick the link below", bg="#101418", fg="white"))
    assert "verify" in out.text.lower()


@needs_tesseract
def test_small_image_is_upscaled_and_read():
    out = ocr.extract_text(png("Send your PIN now", size=(420, 120), font_size=26))
    assert "pin" in out.text.lower()


@needs_tesseract
def test_blank_image_reports_no_text_instead_of_crashing():
    with pytest.raises(NoTextFoundError) as e:
        ocr.extract_text(png(None))
    assert "couldn't extract readable text" in e.value.user_message


def test_invalid_bytes_and_empty_rejected():
    with pytest.raises(InvalidImageError):
        ocr.extract_text(b"this is not an image")
    with pytest.raises(InvalidImageError):
        ocr.extract_text(b"")


def test_disallowed_format_rejected():
    buf = io.BytesIO()
    Image.new("RGB", (100, 100), "white").save(buf, "GIF")
    with pytest.raises(InvalidImageError):
        ocr.extract_text(buf.getvalue())


def test_oversized_dimensions_rejected(monkeypatch):
    monkeypatch.setenv("SCAMLENS_MAX_IMAGE_PIXELS", "5000")
    with pytest.raises(InvalidImageError):
        ocr.extract_text(png("hello", size=(400, 400)))


def test_clean_drops_symbol_noise_and_collapses_blank_lines():
    assert ocr._clean("Hello   world\n\n\n\n|\n>>\nBye") == "Hello world\n\nBye"
