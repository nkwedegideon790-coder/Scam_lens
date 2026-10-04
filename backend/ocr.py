"""Local OCR with Tesseract: validate, preprocess, extract."""
from __future__ import annotations

import io
import logging
import re
import warnings
from dataclasses import dataclass, field

from PIL import Image, ImageFilter, ImageOps, UnidentifiedImageError

from .config import get_settings
from .errors import InvalidImageError, NoTextFoundError, OCRUnavailableError

try:  # pytesseract is a thin wrapper; the tesseract binary must also be installed
    import pytesseract
    from pytesseract import TesseractError, TesseractNotFoundError
except ImportError:  # pragma: no cover
    pytesseract = None  # type: ignore[assignment]

    class TesseractNotFoundError(Exception):  # type: ignore[no-redef]
        pass

    class TesseractError(Exception):  # type: ignore[no-redef]
        pass

logger = logging.getLogger(__name__)

ALLOWED_FORMATS = {"PNG", "JPEG", "WEBP"}
MAX_LONG_SIDE = 3200
MIN_LONG_SIDE = 1400
MIN_CHARS = 3


@dataclass
class OCRResult:
    text: str
    warnings: list[str] = field(default_factory=list)


def is_available() -> bool:
    if pytesseract is None:
        return False
    try:
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def validate_image(data: bytes) -> Image.Image:
    """Verify bytes are a real PNG/JPEG/WebP of sane dimensions and return a loaded image."""
    if not data:
        raise InvalidImageError("The uploaded file is empty.")
    max_pixels = get_settings().max_image_pixels
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            probe = Image.open(io.BytesIO(data))
            fmt = probe.format
            width, height = probe.size
            probe.verify()
            if fmt not in ALLOWED_FORMATS:
                raise InvalidImageError("Unsupported image type. Upload a PNG, JPG or WebP screenshot.")
            if width * height > max_pixels or width < 20 or height < 20:
                raise InvalidImageError("That image has unsupported dimensions. Upload a normal screenshot.")
            img = Image.open(io.BytesIO(data))
            img.load()
            return img
    except InvalidImageError:
        raise
    except (UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning, OSError, SyntaxError, ValueError) as exc:
        raise InvalidImageError() from exc


def _to_gray(img: Image.Image) -> Image.Image:
    img = ImageOps.exif_transpose(img)
    if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
        rgba = img.convert("RGBA")
        background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        img = Image.alpha_composite(background, rgba)
    return img.convert("L")


def preprocess(img: Image.Image) -> tuple[Image.Image, Image.Image]:
    """Return (primary, fallback) variants tuned for phone screenshots."""
    gray = _to_gray(img)
    long_side = max(gray.size)
    if long_side < MIN_LONG_SIDE:
        scale = min(3.0, MIN_LONG_SIDE / long_side)
        gray = gray.resize((int(gray.width * scale), int(gray.height * scale)), Image.LANCZOS)
    elif long_side > MAX_LONG_SIDE:
        scale = MAX_LONG_SIDE / long_side
        gray = gray.resize((int(gray.width * scale), int(gray.height * scale)), Image.LANCZOS)

    # Dark-mode chats: invert so text is dark on light (Tesseract performs better).
    histogram_mean = sum(i * c for i, c in enumerate(gray.histogram())) / max(1, gray.width * gray.height)
    if histogram_mean < 110:
        gray = ImageOps.invert(gray)

    primary = ImageOps.autocontrast(gray, cutoff=1).filter(ImageFilter.SHARPEN)
    fallback = primary.point(lambda p: 255 if p > 150 else 0, mode="L")
    return primary, fallback


def _clean(text: str) -> str:
    lines = []
    for line in text.replace("\r", "\n").split("\n"):
        line = " ".join(line.split())
        if not line:
            if lines and lines[-1] != "":
                lines.append("")
            continue
        if len(line) <= 2 and not any(ch.isalnum() for ch in line):
            continue  # stray symbols from UI chrome
        lines.append(line)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def _run(img: Image.Image, psm: int) -> str:
    cfg = f"--oem 3 --psm {psm}"
    return pytesseract.image_to_string(
        img, lang=get_settings().ocr_lang, config=cfg, timeout=get_settings().ocr_timeout
    )


def extract_text(data: bytes) -> OCRResult:
    """Run OCR on image bytes. Raises friendly ScamLensError subclasses on failure."""
    img = validate_image(data)
    if pytesseract is None:
        raise OCRUnavailableError(detail="pytesseract is not installed")
    try:
        primary, fallback = preprocess(img)
        text = _clean(_run(primary, 6))
        notes: list[str] = []
        if len(text) < 15:
            alt = _clean(_run(fallback, 11))
            if len(alt) > len(text):
                text = alt
        if len(text) < MIN_CHARS:
            raise NoTextFoundError()
        if len(text) < 25:
            notes.append("Only a small amount of text was found. Check it carefully before analyzing.")
        return OCRResult(text=text, warnings=notes)
    except TesseractNotFoundError as exc:
        logger.error("Tesseract binary not found: %s", exc)
        raise OCRUnavailableError(detail="tesseract binary missing") from exc
    except RuntimeError as exc:  # pytesseract raises RuntimeError on timeout
        logger.warning("OCR timed out or failed: %s", exc)
        raise NoTextFoundError("That image took too long to read. Try a smaller or clearer screenshot.") from exc
    except TesseractError as exc:
        logger.warning("Tesseract error: %s", exc)
        raise NoTextFoundError() from exc
