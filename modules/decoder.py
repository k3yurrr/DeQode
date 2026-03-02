import cv2
from pyzbar.pyzbar import decode, ZBarSymbol
import os

def decode_qr_from_image(image_path):
    """
    Reads an image file and decodes any QR codes found inside.
    
    Args:
        image_path (str): Path to the image file.
        
    Returns:
        list: A list of decoded strings found in the image.
              Returns None if the file doesn't exist.
    """
    # 1. Check if file exists
    if not os.path.exists(image_path):
        print(f"[ERROR] File not found: {image_path}")
        return None

    # 2. Load image using OpenCV
    img = cv2.imread(image_path)
    
    if img is None:
        print(f"[ERROR] Could not load image. Check file format.")
        return None

    # 3. Decode specifically looking for QR codes
    # We use ZBarSymbol.QRCODE to speed it up and avoid false positives from barcodes
    decoded_objects = decode(img, symbols=[ZBarSymbol.QRCODE])

    results = []
    for obj in decoded_objects:
        # data comes as bytes, we need to decode to string
        qr_data = obj.data.decode("utf-8")
        results.append(qr_data)
        
    return results