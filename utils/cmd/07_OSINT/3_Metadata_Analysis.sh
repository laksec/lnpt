#!/bin/bash
# =================================================================
# METADATA ANALYSIS CHEAT SHEET
# =================================================================
# [Version 2.1] | [Author: Your Name] | [Updated: 2024]
# =================================================================

# 1. BASIC METADATA EXTRACTION
# ===========================
exiftool file.pdf                          # Full metadata dump
pdfinfo file.pdf                           # PDF-specific info
strings file.docx | grep "Author"          # Find author in binaries
mdls file.jpg                              # macOS metadata (Spotlight)

# 2. ADVANCED ANALYSIS
# ====================
# Extract GPS coordinates from images:
exiftool -GPSLatitude -GPSLongitude -n image.jpg

# Find hidden metadata in Office docs:
olevba -c file.docm                        # Macro + metadata
python3 oledump.py file.pptx               # PowerPoint analysis

# 3. BULK PROCESSING
# ==================
# Process all files in directory:
exiftool -csv -r ~/Downloads > metadata.csv

# Find documents from specific creator:
find  -type f -exec exiftool {} + | grep -i "Author: John Doe"

# 4. REMOVAL TOOLS
# ================
exiftool -all= file.jpg                    # Strip all metadata
mat2 --inplace file.pdf                    # Privacy-preserving cleaner
pdf-redact-tools -a file.pdf               # PDF metadata sanitizer

# 5. FORENSIC TECHNIQUES
# ======================
# Detect steganography:
steghide info secret.jpg                   # Check for hidden data
binwalk suspicious.png                     # Analyze file structure

# File signature verification:
file --keep-going *                        # Verify real file types
truncate -s 0 suspicious.doc && file suspicious.doc  # Reveal fakes

# 6. AUTOMATION SCRIPTS
# =====================
# Monitor new files for metadata:
inotifywait -m -r -e create ~/Downloads | while read path action file; do
  exiftool "$path$file" | grep -i "creator\|gps"
done

# 7. ONLINE TOOLS
# ===============
# Browser-based analysis:
echo "https://www.metadataanalysis.com/analyze?url=$(base64 -w0 file.jpg)"
# Alternative: exifdata.com, metapicz.com

# =================================================================
# PRO TIPS:
# 1. Combine with Google Dorking: filetype:pdf "Author: John Doe"
# 2. Check document revisions: exiftool -TrackChanges file.doc
# 3. Verify timestamps: stat file.txt (Linux/Mac)
# 4. Analyze network captures: tshark -r capture.pcap -Y "http"
# =================================================================

# Usage Examples:
# 1. Quick Analysis
exiftool suspicious.pdf | grep -i "creator\|modified"

# 2. Find All GPS-Tagged Photos
exiftool -r -GPSLatitude -GPSLongitude -n ~/Pictures

# 3. Clean Sensitive Files
find  -name "*.docx" -exec mat2 --inplace {} \;

# 4. Detect Fake Files
file --keep-going * | grep "Microsoft Word" | grep -v "DOCX"

# 5. Extract Hidden Data
binwalk -e suspicious.jpg && strings _suspicious.jpg.extracted/*
