#!/usr/bin/env python3
"""
Generate social preview image for GitHub repository.

Creates a 1200×630px PNG image with text:
"Bitcoin Address-Collision Lab | btc-brute-force"

Requirements:
    pip install Pillow
"""

from PIL import Image, ImageDraw, ImageFont
import os

# Image dimensions (GitHub social preview standard)
WIDTH = 1200
HEIGHT = 630

# Colors (dark theme)
BG_COLOR = (18, 18, 18)  # Dark gray/black
TEXT_COLOR = (255, 147, 0)  # Bitcoin orange
ACCENT_COLOR = (255, 255, 255)  # White for subtitle

def create_social_preview():
    # Create image
    img = Image.new('RGB', (WIDTH, HEIGHT), color=BG_COLOR)
    draw = ImageDraw.Draw(img)
    
    # Try to use a nice font, fallback to default
    try:
        # Try system fonts (macOS)
        title_font = ImageFont.truetype("/System/Library/Fonts/HelveticaNeue.ttc", 72)
        subtitle_font = ImageFont.truetype("/System/Library/Fonts/HelveticaNeue.ttc", 48)
    except:
        try:
            # Try Linux fonts
            title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 72)
            subtitle_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 48)
        except:
            # Fallback to default font
            title_font = ImageFont.load_default()
            subtitle_font = ImageFont.load_default()
    
    # Main title
    title = "Bitcoin Address-Collision Lab"
    title_bbox = draw.textbbox((0, 0), title, font=title_font)
    title_width = title_bbox[2] - title_bbox[0]
    title_height = title_bbox[3] - title_bbox[1]
    title_x = (WIDTH - title_width) // 2
    title_y = HEIGHT // 2 - title_height - 20
    
    draw.text((title_x, title_y), title, fill=TEXT_COLOR, font=title_font)
    
    # Subtitle
    subtitle = "btc-brute-force"
    subtitle_bbox = draw.textbbox((0, 0), subtitle, font=subtitle_font)
    subtitle_width = subtitle_bbox[2] - subtitle_bbox[0]
    subtitle_x = (WIDTH - subtitle_width) // 2
    subtitle_y = title_y + title_height + 30
    
    draw.text((subtitle_x, subtitle_y), subtitle, fill=ACCENT_COLOR, font=subtitle_font)
    
    # Save image
    output_path = os.path.join(os.path.dirname(__file__), 'social-preview.png')
    img.save(output_path, 'PNG')
    print(f"Social preview image created: {output_path}")
    print(f"Dimensions: {WIDTH}×{HEIGHT}px")

if __name__ == '__main__':
    create_social_preview()

