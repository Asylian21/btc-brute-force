# Social Preview Image

This directory contains the social preview image for GitHub repository.

## Generating the Image

The social preview image can be generated using the included Python script:

```bash
# Install Pillow if needed
pip3 install Pillow

# Generate image
python3 create-social-preview.py
```

This creates `social-preview.png` (1200×630px) with the text:

- **Title**: "Bitcoin Address-Collision Lab"
- **Subtitle**: "btc-brute-force"

## Manual Creation

If you prefer to create the image manually:

1. **Dimensions**: 1200×630 pixels (GitHub social preview standard)
2. **Format**: PNG
3. **Text**:
   - "Bitcoin Address-Collision Lab | btc-brute-force"
4. **Style**:
   - Dark background (#121212 or similar)
   - Bitcoin orange (#FF9300) for main text
   - White (#FFFFFF) for subtitle

## Uploading to GitHub

1. Go to repository Settings → General
2. Scroll to "Social preview"
3. Click "Upload an image"
4. Select `social-preview.png`
5. Save changes

The image will appear when sharing the repository on social media and in GitHub's UI.
