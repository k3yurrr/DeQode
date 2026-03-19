import cv2
from pyzbar.pyzbar import decode, ZBarSymbol
import os
import numpy as np

def decode_qr_from_image(image_path):
    """
    Reads an image file and decodes any QR codes found inside.
    Implements multiple detection strategies to handle various image conditions.
    
    Args:
        image_path (str): Path to the image file.
        
    Returns:
        list: A list of decoded strings found in the image.
              Returns empty list if no QR codes found.
    """
    # 1. Check if file exists
    if not os.path.exists(image_path):
        print(f"[ERROR] File not found: {image_path}")
        return []

    # 2. Load image using OpenCV
    img = cv2.imread(image_path)
    
    if img is None:
        print(f"[ERROR] Could not load image. Check file format.")
        return []

    # 3. Try decoding with multiple strategies
    results = []
    
    # Strategy 1: Try original image
    results = _try_decode(img)
    if results:
        return results
    
    # Strategy 2: Try rotations (90, 180, 270 degrees)
    for angle in [90, 180, 270]:
        rotated = _rotate_image(img, angle)
        results = _try_decode(rotated)
        if results:
            print(f"[DEBUG] QR found after {angle}° rotation")
            return results
    
    # Strategy 3: Try with preprocessing (contrast enhancement)
    enhanced = _enhance_contrast(img)
    results = _try_decode(enhanced)
    if results:
        print("[DEBUG] QR found with contrast enhancement")
        return results
    
    # Strategy 4: Try with Gaussian blur to reduce noise
    blurred = cv2.GaussianBlur(img, (5, 5), 0)
    results = _try_decode(blurred)
    if results:
        print("[DEBUG] QR found after denoising")
        return results
    
    # Strategy 5: Try with increased resolution (upscaling)
    if img.shape[0] < 400 or img.shape[1] < 400:
        upscaled = cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
        results = _try_decode(upscaled)
        if results:
            print("[DEBUG] QR found at upscaled resolution")
            return results
    
    # Strategy 6: Try grayscale conversion
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    results = _try_decode(gray)
    if results:
        print("[DEBUG] QR found in grayscale")
        return results
    
    # Strategy 7: Try with adaptive thresholding
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    thresh = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                                   cv2.THRESH_BINARY, 11, 2)
    results = _try_decode(thresh)
    if results:
        print("[DEBUG] QR found with adaptive thresholding")
        return results
    
    print("[DEBUG] No QR code detected after all strategies")
    return []

def _try_decode(img):
    """
    Attempt to decode QR codes from a given image.
    """
    try:
        decoded_objects = decode(img, symbols=[ZBarSymbol.QRCODE])
        results = []
        for obj in decoded_objects:
            try:
                qr_data = obj.data.decode("utf-8")
                results.append(qr_data)
            except:
                # Try latin-1 if utf-8 fails
                try:
                    qr_data = obj.data.decode("latin-1")
                    results.append(qr_data)
                except:
                    results.append(str(obj.data))
        return results
    except Exception as e:
        print(f"[DEBUG] Decode attempt failed: {e}")
        return []

def _rotate_image(img, angle):
    """Rotate image by specified angle."""
    h, w = img.shape[:2]
    center = (w // 2, h // 2)
    matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
    rotated = cv2.warpAffine(img, matrix, (w, h))
    return rotated

def _enhance_contrast(img):
    """Enhance image contrast using CLAHE."""
    if len(img.shape) == 3:
        img_gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    else:
        img_gray = img
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(img_gray)
    return enhanced