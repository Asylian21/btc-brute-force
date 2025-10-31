# Social Preview Image Instructions

## Requirements

Create a 1200×630px PNG image with the following text:

**Title:** "Bitcoin Address-Collision Lab"  
**Subtitle:** "btc-brute-force"

## Design Guidelines

- **Background**: Dark (#121212 or similar)
- **Title Color**: Bitcoin orange (#FF9300)
- **Subtitle Color**: White (#FFFFFF)
- **Font**: Sans-serif, bold for title, regular for subtitle
- **Layout**: Centered text, title larger than subtitle

## Quick Generation Options

### Option 1: Python + Pillow

```bash
pip3 install Pillow
python3 create-social-preview.py
```

### Option 2: Online Tools

Use online image editors like:
- Canva (1200×630 template)
- Figma
- GIMP / Photoshop

### Option 3: ImageMagick

```bash
convert -size 1200x630 xc:'#121212' \
  -font Helvetica-Bold -pointsize 72 -fill '#FF9300' \
  -gravity center -annotate +0-50 "Bitcoin Address-Collision Lab" \
  -font Helvetica -pointsize 48 -fill white \
  -gravity center -annotate +0+50 "btc-brute-force" \
  social-preview.png
```

## Upload to GitHub

1. Settings → General → Social preview
2. Upload `social-preview.png`
3. Save

The image will appear when sharing the repository on social media.
