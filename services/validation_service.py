import magic
from PIL import Image, UnidentifiedImageError
import filetype
import io

def validate_image(file_bytes: bytes, filename: str) -> dict:
    """
    Validates if the provided file is a legitimate image.
    Returns a dictionary with status and details.
    """
    results = {
        "is_valid": True,
        "mime_type": "unknown",
        "magic_bytes": "unknown",
        "is_corrupted": False,
        "errors": []
    }
    
    # 1. Check Magic Bytes
    try:
        mime = magic.Magic(mime=True)
        results["magic_bytes"] = mime.from_buffer(file_bytes)
        results["mime_type"] = results["magic_bytes"]
    except Exception as e:
        results["errors"].append(f"Magic bytes check failed: {str(e)}")
        
    # 2. Check using filetype library as fallback
    kind = filetype.guess(file_bytes)
    if kind:
        if kind.mime != results["magic_bytes"] and results["magic_bytes"] == "unknown":
            results["mime_type"] = kind.mime

    # Check if the detected type is an image
    if not results["mime_type"].startswith("image/"):
        results["is_valid"] = False
        results["errors"].append(f"File is not an image. Detected type: {results['mime_type']}")

    # 3. Validate true image structure with Pillow
    try:
        img = Image.open(io.BytesIO(file_bytes))
        img.verify() # Verify structure without loading full raster data
    except UnidentifiedImageError:
        results["is_valid"] = False
        results["is_corrupted"] = True
        results["errors"].append("Image structure is corrupted or unreadable.")
    except Exception as e:
        results["is_valid"] = False
        results["is_corrupted"] = True
        results["errors"].append(f"Image verification failed: {str(e)}")

    return results
