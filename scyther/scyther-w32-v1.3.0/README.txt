Scyther v1.3.0 - w32

To run Scyther:
1. Extract this archive
2. Run: python3 scyther-gui.py

Requirements:
- Python 3
- wxPython 4.0+ (will be auto-installed if missing)

macOS Security Note:
If macOS blocks the binary, you can remove the quarantine attribute:
  xattr -d com.apple.quarantine scyther-gui.py
  xattr -dr com.apple.quarantine Scyther/

For more information, see:
https://github.com/cascremers/scyther

