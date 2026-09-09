from PIL import Image, ImageDraw, ImageFont
import numpy as np

# 1. Create a base canvas
w, h = 1000, 600
img = Image.new("RGB", (w, h), color=(240, 243, 246))
draw = ImageDraw.Draw(img)

# 2. Draw non-government header & Specimen watermark
draw.rectangle([(0, 0), (w, 80)], fill=(30, 41, 59))
draw.text((30, 25), "IDSHIELD TEST SPECIMEN // NON-OFFICIAL BENCHMARK", fill=(255, 255, 255))

# Diagonal SPECIMEN watermark
draw.text((260, 260), "SPECIMEN ONLY", fill=(210, 215, 220))

# 3. Add a placeholder portrait box
draw.rectangle([(60, 140), (280, 420)], fill=(200, 210, 220), outline=(100, 116, 139), width=2)
draw.text((120, 270), "PHOTO AREA", fill=(71, 85, 105))

# 4. Add test metadata fields
draw.text((340, 150), "Name: Test Subject Alpha", fill=(15, 23, 42))
draw.text((340, 200), "DOB: 01/01/1990", fill=(15, 23, 42))
draw.text((340, 250), "Gender: NOT APPLICABLE", fill=(15, 23, 42))

# 5. Intentional Trigger 1: Invalid 12-digit number (Fails Verhoeff checksum)
# "1234 5678 9012" mathematically violates the Dihedral D5 check
draw.text((340, 340), "1234 5678 9012", fill=(15, 23, 42))

# 6. Intentional Trigger 2: Draw a generic corrupted QR matrix box
draw.rectangle([(750, 140), (940, 330)], fill=(255, 255, 255), outline=(0, 0, 0), width=2)
# Irregular blocks to simulate an unreadable/corrupted QR code
for x in range(770, 920, 30):
    for y in range(160, 310, 30):
        if (x + y) % 20 == 0:
            draw.rectangle([(x, y), (x + 20, y + 20)], fill=(0, 0, 0))

# Save baseline image at standard quality
base_path = "test_specimen_base.jpg"
img.save(base_path, "JPEG", quality=95)

# 7. Intentional Trigger 3: Splice a modified text block to trigger ELA
# Modifying a saved JPEG and pasting it back causes DCT compression discrepancies
spliced_img = Image.open(base_path)
spliced_draw = ImageDraw.Draw(spliced_img)

# Paste a solid patch over DOB and write new text (simulating tampering)
spliced_draw.rectangle([(380, 195), (550, 225)], fill=(255, 255, 255))
spliced_draw.text((385, 200), "DOB: 15/08/2005", fill=(220, 38, 38))

# Save the final test artifact
final_path = "test_specimen_tampered.jpg"
spliced_img.save(final_path, "JPEG", quality=75)

print(f"[+] Created synthetic test artifact: {final_path}")