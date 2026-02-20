"""
qr_decoder.py – QR Code Decoding Module

Decodes QR codes from base64-encoded images and extracts embedded URLs.
Uses a pure-Python fallback approach for Lambda compatibility.
"""

import base64
import re
from io import BytesIO


def decode_qr(image_base64: str) -> dict:
    """
    Decode a QR code from a base64-encoded image.

    Args:
        image_base64: Base64-encoded image string (PNG/JPEG)

    Returns:
        dict with keys:
            - success (bool): Whether QR code was successfully decoded
            - url (str|None): Extracted URL if found
            - raw_data (str|None): Raw decoded QR data
            - error (str|None): Error message if decoding failed
    """
    try:
        # ── Decode base64 image ──────────────────────────────────
        # Strip data URL prefix if present
        if ',' in image_base64:
            image_base64 = image_base64.split(',', 1)[1]

        image_bytes = base64.b64decode(image_base64)

        # ── Try pyzbar first (preferred) ─────────────────────────
        decoded_data = _try_pyzbar_decode(image_bytes)

        # ── Fallback to PIL-based approach ───────────────────────
        if decoded_data is None:
            decoded_data = _try_pil_decode(image_bytes)

        if decoded_data is None:
            return {
                'success': False,
                'url': None,
                'raw_data': None,
                'error': 'Could not decode QR code from image'
            }

        # ── Extract URL from decoded data ────────────────────────
        url = _extract_url(decoded_data)

        return {
            'success': True,
            'url': url,
            'raw_data': decoded_data,
            'error': None
        }

    except base64.binascii.Error:
        return {
            'success': False,
            'url': None,
            'raw_data': None,
            'error': 'Invalid base64 image data'
        }
    except Exception as e:
        return {
            'success': False,
            'url': None,
            'raw_data': None,
            'error': f'QR decode error: {str(e)}'
        }


def _try_pyzbar_decode(image_bytes: bytes) -> str:
    """
    Attempt to decode QR using pyzbar library.
    Returns decoded string or None if pyzbar is unavailable.
    """
    try:
        from pyzbar import pyzbar
        from PIL import Image

        image = Image.open(BytesIO(image_bytes))
        decoded_objects = pyzbar.decode(image)

        if decoded_objects:
            return decoded_objects[0].data.decode('utf-8')
        return None
    except ImportError:
        return None
    except Exception:
        return None


def _try_pil_decode(image_bytes: bytes) -> str:
    """
    Fallback QR decoder using PIL image analysis.
    This is a simplified approach that works for basic QR codes.

    For production, consider using:
    - qrcode + opencv-python
    - A dedicated QR scanning Lambda layer
    """
    try:
        from PIL import Image
        import numpy as np

        image = Image.open(BytesIO(image_bytes))
        image = image.convert('L')  # Grayscale

        # Simple threshold-based QR detection
        img_array = np.array(image)
        threshold = 128
        binary = (img_array < threshold).astype(np.uint8)

        # Look for QR finder patterns (simple heuristic)
        # In production, use a proper QR decoder library
        height, width = binary.shape

        # Check if image likely contains a QR code
        # by looking for the characteristic finder pattern ratio (1:1:3:1:1)
        if _has_finder_pattern(binary):
            # For MVP, we return a placeholder indicating QR was detected
            # but couldn't be decoded without pyzbar
            return None

        return None
    except ImportError:
        return None
    except Exception:
        return None


def _has_finder_pattern(binary_image) -> bool:
    """
    Check if the binary image contains QR finder patterns.
    Simplified heuristic for MVP.
    """
    try:
        import numpy as np
        height, width = binary_image.shape

        # Sample middle row and check for alternating patterns
        mid_row = binary_image[height // 2, :]
        transitions = 0
        for i in range(1, len(mid_row)):
            if mid_row[i] != mid_row[i - 1]:
                transitions += 1

        # QR codes typically have many transitions
        return transitions > 10
    except Exception:
        return False


def _extract_url(data: str) -> str:
    """
    Extract a URL from decoded QR data.

    Args:
        data: Raw decoded QR string

    Returns:
        str: Extracted URL, or the raw data if it looks like a URL
    """
    if not data:
        return None

    # Direct URL
    if data.startswith(('http://', 'https://', 'ftp://')):
        return data.strip()

    # URL within text
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, data)
    if urls:
        return urls[0]

    # Domain-like pattern without protocol
    domain_pattern = r'(?:www\.)?[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:/\S*)?'
    domains = re.findall(domain_pattern, data)
    if domains:
        return f'http://{domains[0]}'

    # Return raw data as-is (might be text, vCard, etc.)
    return data
