import sys, os, io, requests, json, math
from PIL import Image, ExifTags, TiffImagePlugin, PngImagePlugin
import exifread
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit,
    QLabel, QLineEdit, QFileDialog, QMessageBox, QTabWidget, QProgressBar,
    QSplitter, QCheckBox, QFrame, QGridLayout, QScrollArea, QGroupBox,
    QProgressBar, QSpacerItem, QSizePolicy
)
from PyQt5.QtGui import QFont, QColor, QPalette, QPixmap, QIcon, QPainter, QLinearGradient
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QPropertyAnimation, QEasingCurve, pyqtProperty
from datetime import datetime
import hashlib
import platform
from collections import OrderedDict, Counter
import binascii
import struct

class AnimatedCard(QFrame):
    def __init__(self, title="", content="", parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2a2a3a, stop:1 #1a1a2a);
                border-radius: 12px;
                border: 1px solid #444;
                padding: 15px;
            }
            QFrame:hover {
                border: 1px solid #ff6961;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #3a3a4a, stop:1 #2a2a3a);
            }
        """)
        
        self.layout = QVBoxLayout(self)
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet("""
            QLabel {
                color: #ff6961;
                font-weight: bold;
                font-size: 14px;
                padding-bottom: 8px;
                border-bottom: 1px solid #444;
            }
        """)
        self.layout.addWidget(self.title_label)
        
        self.content_label = QLabel(content)
        self.content_label.setStyleSheet("color: #cccccc; font-size: 12px;")
        self.content_label.setWordWrap(True)
        self.layout.addWidget(self.content_label)
        
        # Animation
        self._opacity = 1.0
        self.animation = QPropertyAnimation(self, b"opacity")
        self.animation.setDuration(500)
        self.animation.setEasingCurve(QEasingCurve.OutCubic)

    @pyqtProperty(float)
    def opacity(self):
        return self._opacity

    @opacity.setter
    def opacity(self, value):
        self._opacity = value
        self.setWindowOpacity(value)

    def mousePressEvent(self, event):
        self.animation.setStartValue(1.0)
        self.animation.setEndValue(0.7)
        self.animation.start()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        self.animation.setStartValue(0.7)
        self.animation.setEndValue(1.0)
        self.animation.start()
        super().mouseReleaseEvent(event)

class MetadataExtractionThread(QThread):
    progress_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(dict)
    error_signal = pyqtSignal(str)

    def __init__(self, file_path=None, url=None):
        super().__init__()
        self.file_path = file_path
        self.url = url
        self.data = None

    def run(self):
        try:
            if self.url:
                self.progress_signal.emit("Downloading image from URL...")
                response = requests.get(self.url, timeout=15)
                response.raise_for_status()
                self.data = io.BytesIO(response.content)
                self.extract_all_metadata(self.data, self.url)
            else:
                self.progress_signal.emit("Reading local file...")
                with open(self.file_path, "rb") as f:
                    self.data = io.BytesIO(f.read())
                self.extract_all_metadata(self.data, self.file_path)
        except Exception as e:
            self.error_signal.emit(str(e))

    def extract_all_metadata(self, data, source):
        try:
            result = {}
            
            # Reset stream position
            data.seek(0)
            
            # Basic file analysis
            self.progress_signal.emit("Analyzing file structure...")
            result['file_analysis'] = self.analyze_file(data, source)
            
            # PIL EXIF extraction
            self.progress_signal.emit("Extracting EXIF metadata...")
            data.seek(0)
            result['pil_exif'] = self.extract_pil_exif(data)
            
            # EXIFRead extraction
            self.progress_signal.emit("Extracting detailed EXIF...")
            data.seek(0)
            result['exifread_data'] = self.extract_exifread(data)
            
            # Image properties
            self.progress_signal.emit("Analyzing image properties...")
            data.seek(0)
            result['image_properties'] = self.analyze_image_properties(data)
            
            # Hidden metadata
            self.progress_signal.emit("Searching for hidden metadata...")
            data.seek(0)
            result['hidden_metadata'] = self.find_hidden_metadata(data)
            
            # GPS analysis
            self.progress_signal.emit("Analyzing GPS data...")
            data.seek(0)
            result['gps_data'] = self.extract_gps_data(data)
            
            # Thumbnail analysis
            self.progress_signal.emit("Analyzing thumbnails...")
            data.seek(0)
            result['thumbnail_info'] = self.analyze_thumbnails(data)
            
            # Camera and lens info
            self.progress_signal.emit("Extracting camera information...")
            data.seek(0)
            result['camera_info'] = self.extract_camera_info(data)
            
            # Digital forensics
            self.progress_signal.emit("Performing forensic analysis...")
            data.seek(0)
            result['forensic_data'] = self.forensic_analysis(data, source)
            
            # Enhanced analysis
            self.progress_signal.emit("Performing enhanced analysis...")
            data.seek(0)
            result['enhanced_analysis'] = self.enhanced_analysis(data, source)
            
            self.finished_signal.emit(result)
            
        except Exception as e:
            self.error_signal.emit(f"Extraction error: {str(e)}")

    def analyze_file(self, data, source):
        file_info = {}
        data.seek(0)
        original_data = data.read()
        
        # File hash
        file_info['md5'] = hashlib.md5(original_data).hexdigest()
        file_info['sha1'] = hashlib.sha1(original_data).hexdigest()
        file_info['sha256'] = hashlib.sha256(original_data).hexdigest()
        file_info['sha512'] = hashlib.sha512(original_data).hexdigest()
        
        # File size
        file_info['file_size'] = len(original_data)
        file_info['file_size_mb'] = round(len(original_data) / (1024 * 1024), 2)
        
        # Source info
        file_info['source'] = source
        file_info['analysis_timestamp'] = datetime.now().isoformat()
        
        # File type detection
        file_info['file_signature'] = self.detect_file_signature(original_data[:8])
        
        data.seek(0)
        return file_info

    def detect_file_signature(self, header):
        signatures = {
            b'\xff\xd8\xff': 'JPEG',
            b'\x89PNG\r\n\x1a\n': 'PNG',
            b'BM': 'BMP',
            b'II*\x00': 'TIFF (Little Endian)',
            b'MM\x00*': 'TIFF (Big Endian)',
            b'GIF8': 'GIF',
            b'RIFF': 'WEBP',
            b'\x00\x00\x00 ftyp': 'HEIC'
        }
        
        for sig, file_type in signatures.items():
            if header.startswith(sig):
                return file_type
        return 'Unknown'

    def extract_pil_exif(self, data):
        try:
            image = Image.open(data)
            exif_data = {}
            
            if hasattr(image, '_getexif') and image._getexif():
                exif = image._getexif()
                for tag_id, value in exif.items():
                    tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                    # Handle different data types
                    if isinstance(value, (bytes, bytearray)):
                        try:
                            value = value.decode('utf-8', errors='replace')
                        except:
                            value = f"<binary_data_{len(value)}_bytes>"
                    exif_data[tag_name] = value
                    
            # PNG metadata
            if hasattr(image, 'text'):
                exif_data['png_text'] = dict(image.text)
                
            return exif_data
        except Exception as e:
            return {'error': str(e)}

    def extract_exifread(self, data):
        try:
            data.seek(0)
            tags = exifread.process_file(data, details=True)
            processed_tags = {}
            
            for tag, value in tags.items():
                # Convert to string representation for display
                str_value = str(value)
                if len(str_value) > 200:  # Truncate very long values
                    str_value = str_value[:200] + "..."
                processed_tags[tag] = str_value
                
            return processed_tags
        except Exception as e:
            return {'error': str(e)}

    def analyze_image_properties(self, data):
        try:
            data.seek(0)
            image = Image.open(data)
            props = {}
            
            props['format'] = image.format
            props['mode'] = image.mode
            props['size'] = image.size
            props['width'] = image.width
            props['height'] = image.height
            props['bands'] = image.getbands()
            props['info'] = dict(image.info) if hasattr(image, 'info') and image.info else {}
            
            # Color profile
            if hasattr(image, 'icc_profile'):
                props['has_icc_profile'] = True
                props['icc_profile_size'] = len(image.icc_profile) if image.icc_profile else 0
            else:
                props['has_icc_profile'] = False
                
            return props
        except Exception as e:
            return {'error': str(e)}

    def find_hidden_metadata(self, data):
        hidden = {}
        data.seek(0)
        raw_data = data.read()
        
        # Look for common hidden data patterns
        hidden['jfif_markers'] = self.find_jfif_markers(raw_data)
        hidden['exif_offsets'] = self.find_exif_offsets(raw_data)
        hidden['potential_steganography'] = self.check_steganography_indicators(raw_data)
        hidden['unusual_headers'] = self.check_unusual_headers(raw_data)
        hidden['embedded_files'] = self.scan_embedded_files(raw_data)
        hidden['suspicious_strings'] = self.extract_suspicious_strings(raw_data)
        
        return hidden

    def find_jfif_markers(self, data):
        markers = {}
        jfif_markers = [b'\xff\xe0', b'\xff\xe1', b'\xff\xe2', b'\xff\xed', b'\xfe\xfe']
        for marker in jfif_markers:
            positions = []
            start = 0
            while True:
                pos = data.find(marker, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1
            if positions:
                markers[marker.hex()] = positions
        return markers

    def find_exif_offsets(self, data):
        offsets = {}
        # Look for EXIF header
        exif_header = b'Exif\x00\x00'
        pos = data.find(exif_header)
        if pos != -1:
            offsets['exif_header'] = pos
            
        # Look for XMP data
        xmp_header = b'http://ns.adobe.com/xap/1.0/'
        pos = data.find(xmp_header)
        if pos != -1:
            offsets['xmp_data'] = pos
            
        return offsets

    def check_steganography_indicators(self, data):
        indicators = []
        # Check for LSB steganography patterns
        if len(data) > 1000:
            # Analyze byte distribution
            byte_counts = [0] * 256
            for byte in data[:10000]:  # Sample first 10KB
                if isinstance(byte, int):
                    byte_counts[byte] += 1
            
            # Check for unusual patterns that might indicate steganography
            unusual_zeros = byte_counts[0] / len(data[:10000]) > 0.5
            if unusual_zeros:
                indicators.append("High frequency of zero bytes - possible LSB steganography")
                
            # Check for EOF data
            if data[-2:] != b'\xff\xd9' and b'\xff\xd9' in data:
                indicators.append("Data after JPEG end marker - potential hidden content")
                
        return indicators if indicators else ["No obvious steganography indicators found"]

    def check_unusual_headers(self, data):
        unusual = []
        # Check for non-standard headers
        if data[:4] not in [b'\xff\xd8\xff\xe0', b'\xff\xd8\xff\xe1', b'\x89PNG', b'BM']:
            unusual.append(f"Unusual file header: {data[:4].hex()}")
        return unusual

    def scan_embedded_files(self, data):
        embedded = {}
        # Look for embedded file signatures
        signatures = {
            'ZIP': b'PK\x03\x04',
            'PDF': b'%PDF',
            'GZIP': b'\x1f\x8b',
        }
        
        for file_type, signature in signatures.items():
            pos = data.find(signature)
            if pos != -1:
                embedded[file_type] = pos
                
        return embedded

    def extract_suspicious_strings(self, data):
        suspicious = []
        try:
            # Extract printable strings
            strings = []
            current_string = ""
            for byte in data:
                if isinstance(byte, int) and 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) > 4:
                        strings.append(current_string)
                    current_string = ""
            
            # Check for suspicious patterns
            suspicious_keywords = ['password', 'secret', 'hidden', 'stego', 'encrypt', 'key']
            for string in strings:
                lower_string = string.lower()
                for keyword in suspicious_keywords:
                    if keyword in lower_string:
                        suspicious.append(string)
                        break
                        
        except Exception as e:
            print(f"String extraction error: {e}")
            
        return suspicious[:10]  # Return first 10 suspicious strings

    def extract_gps_data(self, data):
        try:
            data.seek(0)
            tags = exifread.process_file(data)
            gps_info = {}
            
            gps_tags = {tag: value for tag, value in tags.items() if 'GPS' in tag}
            for tag, value in gps_tags.items():
                gps_info[tag] = str(value)
                
            # Try to decode GPS coordinates
            if 'GPS GPSLatitude' in gps_tags and 'GPS GPSLongitude' in gps_tags:
                try:
                    lat = self.decimal_coords(gps_tags['GPS GPSLatitude'])
                    lon = self.decimal_coords(gps_tags['GPS GPSLongitude'])
                    gps_info['decoded_latitude'] = lat
                    gps_info['decoded_longitude'] = lon
                    if lat and lon:
                        gps_info['google_maps_url'] = f"https://maps.google.com/?q={lat},{lon}"
                except Exception as e:
                    gps_info['coordinate_decode_error'] = f"Could not decode coordinates: {str(e)}"
                    
            return gps_info
        except Exception as e:
            return {'error': str(e)}

    def decimal_coords(self, coords):
        """Convert EXIF GPS coordinates to decimal"""
        try:
            if not coords or not coords.values:
                return None
                
            d = float(coords.values[0].num) / float(coords.values[0].den)
            m = float(coords.values[1].num) / float(coords.values[1].den)
            s = float(coords.values[2].num) / float(coords.values[2].den)
            return d + (m / 60.0) + (s / 3600.0)
        except Exception as e:
            print(f"Coordinate conversion error: {e}")
            return None

    def analyze_thumbnails(self, data):
        try:
            data.seek(0)
            image = Image.open(data)
            thumb_info = {}
            
            # Check for embedded thumbnail
            if hasattr(image, 'thumbnail'):
                thumb_info['has_embedded_thumbnail'] = True
                thumb_info['thumbnail_size'] = image.thumbnail.size if image.thumbnail else 'Unknown'
            else:
                thumb_info['has_embedded_thumbnail'] = False
                
            return thumb_info
        except Exception as e:
            return {'error': str(e)}

    def extract_camera_info(self, data):
        try:
            data.seek(0)
            tags = exifread.process_file(data)
            camera_info = {}
            
            camera_fields = {
                'Image Make': 'camera_make',
                'Image Model': 'camera_model',
                'EXIF ExifImageWidth': 'image_width',
                'EXIF ExifImageLength': 'image_height',
                'EXIF FNumber': 'aperture',
                'EXIF ExposureTime': 'exposure_time',
                'EXIF ISOSpeedRatings': 'iso',
                'EXIF FocalLength': 'focal_length',
                'EXIF LensModel': 'lens_model',
                'EXIF LensSerialNumber': 'lens_serial',
                'EXIF SerialNumber': 'camera_serial',
            }
            
            for exif_field, info_field in camera_fields.items():
                if exif_field in tags:
                    camera_info[info_field] = str(tags[exif_field])
                    
            return camera_info
        except Exception as e:
            return {'error': str(e)}

    def forensic_analysis(self, data, source):
        forensic = {}
        
        # File system artifacts (for local files)
        if os.path.exists(source):
            try:
                stat = os.stat(source)
                forensic['file_timestamps'] = {
                    'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'accessed': datetime.fromtimestamp(stat.st_atime).isoformat()
                }
                forensic['file_permissions'] = oct(stat.st_mode)
                forensic['file_inode'] = stat.st_ino
            except Exception as e:
                forensic['file_timestamps_error'] = f"Could not read file timestamps: {str(e)}"
        
        # Metadata consistency checks
        data.seek(0)
        try:
            image = Image.open(data)
            exif = image._getexif() if hasattr(image, '_getexif') and image._getexif() else {}
            
            # Check for metadata tampering indicators
            checks = {}
            
            # Check if creation date is after modification date
            if 'DateTime' in exif and 'DateTimeDigitized' in exif:
                try:
                    create_date = exif['DateTime']
                    digitized_date = exif['DateTimeDigitized']
                    checks['date_consistency'] = create_date == digitized_date
                except Exception as e:
                    checks['date_consistency'] = f'Unknown: {str(e)}'
                    
            forensic['integrity_checks'] = checks
        except Exception as e:
            forensic['integrity_checks_error'] = f"Could not perform integrity checks: {str(e)}"
            
        return forensic

    def enhanced_analysis(self, data, source):
        enhanced = {}
        
        # Deep byte analysis
        data.seek(0)
        raw_data = data.read()
        
        # Calculate entropy
        enhanced['entropy'] = self.calculate_entropy(raw_data[:10000])  # Sample first 10KB
        
        # Check for compression artifacts
        enhanced['compression_analysis'] = self.analyze_compression(raw_data)
        
        # Metadata density
        enhanced['metadata_density'] = self.calculate_metadata_density(raw_data)
        
        return enhanced

    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data - FIXED VERSION"""
        if len(data) == 0:
            return 0.0
        
        try:
            # Count frequency of each byte value
            if isinstance(data, bytes):
                byte_counts = Counter(data)
            else:
                # Convert to bytes if needed
                byte_counts = Counter(data.encode('latin-1') if isinstance(data, str) else data)
            
            # Calculate probabilities and entropy
            entropy = 0.0
            total = len(data)
            
            for count in byte_counts.values():
                # Calculate probability of this byte
                p_x = count / total
                # Calculate entropy contribution
                entropy -= p_x * math.log2(p_x)
                
            return round(entropy, 4)
        except Exception as e:
            print(f"Entropy calculation error: {e}")
            return 0.0

    def analyze_compression(self, data):
        analysis = {}
        try:
            if len(data) > 1000:
                unique_bytes = len(set(data[:1000]))
                analysis['unique_byte_ratio'] = round(unique_bytes / 1000, 4)
                analysis['compression_likelihood'] = "High" if unique_bytes < 200 else "Low"
            else:
                analysis['error'] = "Data too small for compression analysis"
        except Exception as e:
            analysis['error'] = f"Compression analysis failed: {str(e)}"
        return analysis

    def calculate_metadata_density(self, data):
        try:
            # Count metadata-like patterns
            metadata_indicators = [b'Exif', b'JFIF', b'Photoshop', b'Adobe', b'GPS', b'ICC']
            count = 0
            for indicator in metadata_indicators:
                count += data.count(indicator)
            return count
        except Exception as e:
            print(f"Metadata density calculation error: {e}")
            return 0


class AdvancedExifMasterPro(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔍 Yoka Exiftool Pro Ultra - Advanced Metadata Forensic Analyzer")
        self.setGeometry(50, 50, 1400, 1000)
        self.current_file_path = None
        self.analysis_results = None
        self.init_ui()

    def init_ui(self):
        # Dark theme with professional colors
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(15, 15, 25))
        palette.setColor(QPalette.WindowText, QColor(220, 220, 220))
        palette.setColor(QPalette.Base, QColor(25, 25, 35))
        palette.setColor(QPalette.Text, QColor(255, 105, 97))
        palette.setColor(QPalette.Button, QColor(45, 45, 60))
        palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        palette.setColor(QPalette.Highlight, QColor(255, 105, 97))
        self.setPalette(palette)

        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(15, 15, 15, 15)

        # Header with gradient effect
        header = QLabel("🕵️ Yoka Exif Pro Ultra - Advanced Digital Forensics & Metadata Analysis")
        header.setFont(QFont("Segoe UI", 18, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("""
            QLabel {
                color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff6961, stop:0.5 #ff8c42, stop:1 #ff6961);
                padding: 15px;
                background-color: #1a1a2a;
                border-radius: 10px;
                border: 1px solid #444;
            }
        """)
        main_layout.addWidget(header)

        # Multi-bar input section
        input_container = QFrame()
        input_container.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2a2a3a, stop:1 #1a1a2a);
                border-radius: 10px;
                border: 1px solid #444;
                padding: 10px;
            }
        """)
        input_layout = QVBoxLayout(input_container)
        
        # URL input bar
        url_bar = QHBoxLayout()
        url_label = QLabel("🌐 Image URL:")
        url_label.setFont(QFont("Segoe UI", 11, QFont.Bold))
        url_label.setStyleSheet("color: #ff8c42;")
        url_bar.addWidget(url_label)
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Paste image URL for remote analysis...")
        self.url_input.setFont(QFont("Consolas", 10))
        self.url_input.setStyleSheet("""
            QLineEdit {
                background: #1a1a2a;
                border: 2px solid #444;
                border-radius: 8px;
                padding: 8px;
                color: #ffffff;
                font-size: 12px;
            }
            QLineEdit:focus {
                border: 2px solid #ff6961;
            }
        """)
        url_bar.addWidget(self.url_input)

        self.btn_url = QPushButton("🔍 Analyze URL")
        self.btn_url.clicked.connect(self.analyze_from_url)
        self.btn_url.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.btn_url.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ff6961, stop:1 #e05555);
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ff7a6d, stop:1 #e86666);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #e05555, stop:1 #cc4444);
            }
        """)
        url_bar.addWidget(self.btn_url)
        input_layout.addLayout(url_bar)

        # File operations bar
        file_bar = QHBoxLayout()
        self.btn_file = QPushButton("📁 Upload & Analyze Local Image")
        self.btn_file.clicked.connect(self.analyze_from_file)
        self.btn_file.setFont(QFont("Segoe UI", 11, QFont.Bold))
        self.btn_file.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #42a5ff, stop:1 #1e88e5);
                border: none;
                border-radius: 8px;
                padding: 12px 25px;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #5bb3ff, stop:1 #3399ff);
            }
        """)
        file_bar.addWidget(self.btn_file)

        self.btn_export = QPushButton("💾 Export Full Report")
        self.btn_export.clicked.connect(self.export_report)
        self.btn_export.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.btn_export.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #66bb6a, stop:1 #4caf50);
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                color: white;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #81c784, stop:1 #66bb6a);
            }
            QPushButton:disabled {
                background: #666666;
                color: #999999;
            }
        """)
        self.btn_export.setEnabled(False)
        file_bar.addWidget(self.btn_export)

        self.btn_clear = QPushButton("🗑️ Clear Results")
        self.btn_clear.clicked.connect(self.clear_results)
        self.btn_clear.setFont(QFont("Segoe UI", 10))
        self.btn_clear.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ff6b6b, stop:1 #ee5a52);
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                color: white;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ff7979, stop:1 #ff6b6b);
            }
        """)
        file_bar.addWidget(self.btn_clear)
        input_layout.addLayout(file_bar)

        main_layout.addWidget(input_container)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #444;
                border-radius: 8px;
                text-align: center;
                background: #1a1a2a;
                color: white;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #ff6961, stop:0.5 #ff8c42, stop:1 #ff6961);
                border-radius: 6px;
            }
        """)
        main_layout.addWidget(self.progress_bar)

        # Dashboard Cards
        self.create_dashboard_cards(main_layout)

        # Results area with tabs
        self.tabs = QTabWidget()
        self.tabs.setFont(QFont("Segoe UI", 10))
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #444;
                border-radius: 8px;
                background: #1a1a2a;
            }
            QTabBar::tab {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2a2a3a, stop:1 #1a1a2a);
                border: 1px solid #444;
                border-bottom: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                padding: 8px 16px;
                color: #cccccc;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ff6961, stop:1 #e05555);
                color: white;
            }
            QTabBar::tab:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #3a3a4a, stop:1 #2a2a3a);
            }
        """)
        
        # Create tabs
        self.create_tabs()
        main_layout.addWidget(self.tabs)

        self.setLayout(main_layout)

    def create_dashboard_cards(self, main_layout):
        # Dashboard section
        dashboard_label = QLabel("📊 Quick Analysis Dashboard")
        dashboard_label.setFont(QFont("Segoe UI", 14, QFont.Bold))
        dashboard_label.setStyleSheet("color: #ff8c42; padding: 10px 0px;")
        main_layout.addWidget(dashboard_label)

        # Cards container
        self.cards_scroll = QScrollArea()
        self.cards_scroll.setWidgetResizable(True)
        self.cards_scroll.setFixedHeight(180)
        self.cards_scroll.setStyleSheet("""
            QScrollArea {
                border: 1px solid #444;
                border-radius: 10px;
                background: transparent;
            }
            QScrollArea > QWidget > QWidget {
                background: transparent;
            }
        """)
        
        self.cards_widget = QWidget()
        self.cards_layout = QHBoxLayout(self.cards_widget)
        self.cards_layout.setSpacing(15)
        self.cards_layout.setContentsMargins(15, 10, 15, 10)
        
        # Initialize cards
        self.card_file = AnimatedCard("📁 File Info", "No file analyzed")
        self.card_camera = AnimatedCard("📷 Camera", "No camera data")
        self.card_gps = AnimatedCard("🌍 Location", "No GPS data")
        self.card_security = AnimatedCard("🔒 Security", "No security analysis")
        self.card_metadata = AnimatedCard("📊 Metadata", "No metadata extracted")
        
        self.cards_layout.addWidget(self.card_file)
        self.cards_layout.addWidget(self.card_camera)
        self.cards_layout.addWidget(self.card_gps)
        self.cards_layout.addWidget(self.card_security)
        self.cards_layout.addWidget(self.card_metadata)
        
        self.cards_scroll.setWidget(self.cards_widget)
        main_layout.addWidget(self.cards_scroll)

    def create_tabs(self):
        # Overview tab
        self.overview_text = QTextEdit()
        self.overview_text.setReadOnly(True)
        self.overview_text.setFont(QFont("Consolas", 9))
        self.overview_text.setStyleSheet("background: #1a1a2a; color: #cccccc; border: none;")
        self.tabs.addTab(self.overview_text, "📊 Overview")
        
        # EXIF tab
        self.exif_text = QTextEdit()
        self.exif_text.setReadOnly(True)
        self.exif_text.setFont(QFont("Consolas", 9))
        self.exif_text.setStyleSheet("background: #1a1a2a; color: #cccccc; border: none;")
        self.tabs.addTab(self.exif_text, "📸 EXIF Data")
        
        # Camera tab
        self.camera_text = QTextEdit()
        self.camera_text.setReadOnly(True)
        self.camera_text.setFont(QFont("Consolas", 9))
        self.camera_text.setStyleSheet("background: #1a1a2a; color: #cccccc; border: none;")
        self.tabs.addTab(self.camera_text, "📷 Camera Info")
        
        # GPS tab
        self.gps_text = QTextEdit()
        self.gps_text.setReadOnly(True)
        self.gps_text.setFont(QFont("Consolas", 9))
        self.gps_text.setStyleSheet("background: #1a1a2a; color: #cccccc; border: none;")
        self.tabs.addTab(self.gps_text, "🌍 GPS Data")
        
        # Forensic tab
        self.forensic_text = QTextEdit()
        self.forensic_text.setReadOnly(True)
        self.forensic_text.setFont(QFont("Consolas", 9))
        self.forensic_text.setStyleSheet("background: #1a1a2a; color: #cccccc; border: none;")
        self.tabs.addTab(self.forensic_text, "🔎 Forensic Analysis")
        
        # Hidden Data tab
        self.hidden_text = QTextEdit()
        self.hidden_text.setReadOnly(True)
        self.hidden_text.setFont(QFont("Consolas", 9))
        self.hidden_text.setStyleSheet("background: #1a1a2a; color: #cccccc; border: none;")
        self.tabs.addTab(self.hidden_text, "🕵️ Hidden Metadata")
        
        # Enhanced Analysis tab
        self.enhanced_text = QTextEdit()
        self.enhanced_text.setReadOnly(True)
        self.enhanced_text.setFont(QFont("Consolas", 9))
        self.enhanced_text.setStyleSheet("background: #1a1a2a; color: #cccccc; border: none;")
        self.tabs.addTab(self.enhanced_text, "🔬 Enhanced Analysis")

    def analyze_from_url(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a valid image URL.")
            return
        
        self.start_analysis(url=url)

    def analyze_from_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Image", "",
            "Images (*.jpg *.jpeg *.png *.tiff *.tif *.bmp *.webp *.heic);;All Files (*)"
        )
        if path:
            self.current_file_path = path
            self.start_analysis(file_path=path)

    def start_analysis(self, file_path=None, url=None):
        # Clear previous results
        for text_widget in [self.overview_text, self.exif_text, self.camera_text, 
                          self.gps_text, self.forensic_text, self.hidden_text, self.enhanced_text]:
            text_widget.clear()

        # Reset cards
        self.update_dashboard_cards({})

        # Disable buttons during analysis
        self.btn_url.setEnabled(False)
        self.btn_file.setEnabled(False)
        self.btn_export.setEnabled(False)
        self.btn_clear.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress

        # Start analysis thread
        self.analysis_thread = MetadataExtractionThread(file_path=file_path, url=url)
        self.analysis_thread.progress_signal.connect(self.update_progress)
        self.analysis_thread.finished_signal.connect(self.analysis_finished)
        self.analysis_thread.error_signal.connect(self.analysis_error)
        self.analysis_thread.start()

    def update_progress(self, message):
        self.overview_text.append(f"⏳ {message}")

    def analysis_finished(self, results):
        self.progress_bar.setVisible(False)
        self.btn_url.setEnabled(True)
        self.btn_file.setEnabled(True)
        self.btn_export.setEnabled(True)
        self.btn_clear.setEnabled(True)
        
        self.analysis_results = results
        
        # Update dashboard cards
        self.update_dashboard_cards(results)
        
        # Display results in respective tabs
        self.display_overview(results)
        self.display_exif_data(results)
        self.display_camera_info(results)
        self.display_gps_data(results)
        self.display_forensic_analysis(results)
        self.display_hidden_metadata(results)
        self.display_enhanced_analysis(results)

    def update_dashboard_cards(self, results):
        # File Info Card
        file_info = results.get('file_analysis', {})
        file_content = f"Size: {file_info.get('file_size_mb', 0)} MB\n"
        file_content += f"Type: {file_info.get('file_signature', 'Unknown')}\n"
        file_content += f"SHA256: {file_info.get('sha256', 'N/A')[:16]}..."
        self.card_file.content_label.setText(file_content)

        # Camera Card
        camera_info = results.get('camera_info', {})
        camera_content = f"Make: {camera_info.get('camera_make', 'Unknown')}\n"
        camera_content += f"Model: {camera_info.get('camera_model', 'Unknown')}\n"
        camera_content += f"Lens: {camera_info.get('lens_model', 'Unknown')}"
        self.card_camera.content_label.setText(camera_content)

        # GPS Card
        gps_data = results.get('gps_data', {})
        gps_content = "No GPS Data"
        if 'decoded_latitude' in gps_data and gps_data['decoded_latitude']:
            lat = gps_data['decoded_latitude']
            lon = gps_data['decoded_longitude']
            gps_content = f"Lat: {lat:.4f}\nLon: {lon:.4f}\n📍 Location Found"
        self.card_gps.content_label.setText(gps_content)

        # Security Card
        hidden = results.get('hidden_metadata', {})
        security_content = f"Stego Indicators: {len(hidden.get('potential_steganography', []))}\n"
        security_content += f"Suspicious: {len(hidden.get('suspicious_strings', []))}\n"
        security_content += f"Embedded Files: {len(hidden.get('embedded_files', {}))}"
        self.card_security.content_label.setText(security_content)

        # Metadata Card
        exif_data = results.get('pil_exif', {})
        metadata_content = f"EXIF Tags: {len(exif_data)}\n"
        metadata_content += f"GPS: {'Yes' if gps_data and len(gps_data) > 1 else 'No'}\n"
        metadata_content += f"Thumbnail: {results.get('thumbnail_info', {}).get('has_embedded_thumbnail', False)}"
        self.card_metadata.content_label.setText(metadata_content)

    def analysis_error(self, error_message):
        self.progress_bar.setVisible(False)
        self.btn_url.setEnabled(True)
        self.btn_file.setEnabled(True)
        self.btn_clear.setEnabled(True)
        QMessageBox.critical(self, "Analysis Error", f"Error during analysis:\n{error_message}")

    def display_overview(self, results):
        text = "🔍 Yoka Exif PRO ULTRA - ANALYSIS OVERVIEW\n"
        text += "=" * 60 + "\n\n"
        
        # File information
        file_info = results.get('file_analysis', {})
        text += "📁 FILE INFORMATION:\n"
        text += f"• Source: {file_info.get('source', 'Unknown')}\n"
        text += f"• Size: {file_info.get('file_size_mb', 0)} MB ({file_info.get('file_size', 0)} bytes)\n"
        text += f"• Type: {file_info.get('file_signature', 'Unknown')}\n"
        text += f"• MD5: {file_info.get('md5', 'N/A')}\n"
        text += f"• SHA256: {file_info.get('sha256', 'N/A')}\n"
        text += f"• Analysis Time: {file_info.get('analysis_timestamp', 'N/A')}\n\n"
        
        # Image properties
        img_props = results.get('image_properties', {})
        text += "🖼️ IMAGE PROPERTIES:\n"
        text += f"• Format: {img_props.get('format', 'Unknown')}\n"
        text += f"• Dimensions: {img_props.get('width', '?')} x {img_props.get('height', '?')}\n"
        text += f"• Color Mode: {img_props.get('mode', 'Unknown')}\n"
        text += f"• Has ICC Profile: {img_props.get('has_icc_profile', False)}\n\n"
        
        # Quick summary
        text += "📊 METADATA SUMMARY:\n"
        exif_data = results.get('pil_exif', {})
        text += f"• EXIF Tags Found: {len(exif_data)}\n"
        text += f"• GPS Data: {'Yes' if results.get('gps_data') and len(results['gps_data']) > 1 else 'No'}\n"
        text += f"• Camera Info: {'Yes' if results.get('camera_info') and len(results['camera_info']) > 1 else 'No'}\n"
        
        hidden = results.get('hidden_metadata', {})
        stego_indicators = hidden.get('potential_steganography', [])
        if stego_indicators and len(stego_indicators) > 0:
            text += f"• 🚨 Steganography Indicators: {len(stego_indicators)}\n"
        
        enhanced = results.get('enhanced_analysis', {})
        if enhanced.get('entropy'):
            text += f"• Entropy: {enhanced['entropy']}\n"
        
        self.overview_text.setPlainText(text)

    def display_exif_data(self, results):
        text = "📸 DETAILED EXIF METADATA\n"
        text += "=" * 50 + "\n\n"
        
        # PIL EXIF data
        pil_exif = results.get('pil_exif', {})
        if pil_exif and not pil_exif.get('error'):
            text += "PIL EXIF Data:\n"
            for key, value in pil_exif.items():
                if key != 'error':
                    text += f"{key}: {value}\n"
            text += "\n"
        else:
            text += "No PIL EXIF data found or error occurred.\n\n"
        
        # EXIFRead data
        exifread_data = results.get('exifread_data', {})
        if exifread_data and not exifread_data.get('error'):
            text += "EXIFRead Detailed Data:\n"
            for key, value in exifread_data.items():
                if key != 'error' and not key.startswith('JPEGThumbnail'):
                    text += f"{key}: {value}\n"
        
        self.exif_text.setPlainText(text)

    def display_camera_info(self, results):
        text = "📷 CAMERA & LENS INFORMATION\n"
        text += "=" * 50 + "\n\n"
        
        camera_info = results.get('camera_info', {})
        if camera_info and not camera_info.get('error'):
            for key, value in camera_info.items():
                if key != 'error':
                    text += f"{key.replace('_', ' ').title()}: {value}\n"
        else:
            text += "No detailed camera information found.\n"
        
        # Additional camera info from PIL EXIF
        pil_exif = results.get('pil_exif', {})
        camera_fields = ['Make', 'Model', 'Software', 'Artist', 'Copyright']
        text += "\nAdditional Camera Info:\n"
        for field in camera_fields:
            if field in pil_exif:
                text += f"{field}: {pil_exif[field]}\n"
        
        self.camera_text.setPlainText(text)

    def display_gps_data(self, results):
        text = "🌍 GPS GEOLOCATION DATA\n"
        text += "=" * 50 + "\n\n"
        
        gps_data = results.get('gps_data', {})
        if gps_data and not gps_data.get('error'):
            for key, value in gps_data.items():
                text += f"{key}: {value}\n"
            
            # Show map link if coordinates available
            if 'decoded_latitude' in gps_data and 'decoded_longitude' in gps_data:
                lat = gps_data['decoded_latitude']
                lon = gps_data['decoded_longitude']
                if lat and lon:
                    text += f"\n📍 Google Maps: https://maps.google.com/?q={lat},{lon}\n"
                    text += f"📍 OpenStreetMap: https://www.openstreetmap.org/?mlat={lat}&mlon={lon}\n"
        else:
            text += "No GPS data found in image metadata.\n"
        
        self.gps_text.setPlainText(text)

    def display_forensic_analysis(self, results):
        text = "🔎 DIGITAL FORENSIC ANALYSIS\n"
        text += "=" * 50 + "\n\n"
        
        forensic = results.get('forensic_data', {})
        
        # File timestamps
        timestamps = forensic.get('file_timestamps', {})
        if timestamps:
            text += "📅 FILE TIMESTAMPS:\n"
            text += f"• Created: {timestamps.get('created', 'N/A')}\n"
            text += f"• Modified: {timestamps.get('modified', 'N/A')}\n"
            text += f"• Accessed: {timestamps.get('accessed', 'N/A')}\n\n"
        
        # Integrity checks
        integrity = forensic.get('integrity_checks', {})
        if integrity:
            text += "🔒 INTEGRITY CHECKS:\n"
            for check, result in integrity.items():
                status = "✅ PASS" if result == True else "❌ FAIL" if result == False else "❓ UNKNOWN"
                text += f"• {check.replace('_', ' ').title()}: {status}\n"
        
        self.forensic_text.setPlainText(text)

    def display_hidden_metadata(self, results):
        text = "🕵️ HIDDEN METADATA & STEGANOGRAPHY INDICATORS\n"
        text += "=" * 60 + "\n\n"
        
        hidden = results.get('hidden_metadata', {})
        
        # JFIF markers
        markers = hidden.get('jfif_markers', {})
        if markers:
            text += "📋 JFIF MARKERS FOUND:\n"
            for marker, positions in markers.items():
                text += f"• Marker 0x{marker}: {len(positions)} positions\n"
            text += "\n"
        
        # EXIF offsets
        offsets = hidden.get('exif_offsets', {})
        if offsets:
            text += "📍 EXIF OFFSETS:\n"
            for offset_type, position in offsets.items():
                text += f"• {offset_type}: byte {position}\n"
            text += "\n"
        
        # Steganography indicators
        stego = hidden.get('potential_steganography', [])
        if stego:
            text += "🚨 STEGANOGRAPHY INDICATORS:\n"
            for indicator in stego:
                text += f"• ⚠️ {indicator}\n"
            text += "\n"
        else:
            text += "✅ No obvious steganography indicators detected.\n\n"
        
        # Embedded files
        embedded = hidden.get('embedded_files', {})
        if embedded:
            text += "📎 EMBEDDED FILES DETECTED:\n"
            for file_type, position in embedded.items():
                text += f"• {file_type} at byte {position}\n"
            text += "\n"
        
        # Suspicious strings
        suspicious = hidden.get('suspicious_strings', [])
        if suspicious:
            text += "🔍 SUSPICIOUS STRINGS FOUND:\n"
            for string in suspicious[:5]:  # Show first 5
                text += f"• \"{string}\"\n"
        
        self.hidden_text.setPlainText(text)

    def display_enhanced_analysis(self, results):
        text = "🔬 ENHANCED TECHNICAL ANALYSIS\n"
        text += "=" * 50 + "\n\n"
        
        enhanced = results.get('enhanced_analysis', {})
        
        if enhanced:
            text += "📈 ENTROPY ANALYSIS:\n"
            text += f"• Data Entropy: {enhanced.get('entropy', 'N/A')}\n"
            text += "  (Higher entropy may indicate encrypted/compressed data)\n\n"
            
            compression = enhanced.get('compression_analysis', {})
            text += "🗜️ COMPRESSION ANALYSIS:\n"
            if 'unique_byte_ratio' in compression:
                text += f"• Unique Byte Ratio: {compression.get('unique_byte_ratio', 'N/A')}\n"
                text += f"• Compression Likelihood: {compression.get('compression_likelihood', 'N/A')}\n\n"
            else:
                text += f"• {compression.get('error', 'Analysis failed')}\n\n"
            
            text += "📊 METADATA DENSITY:\n"
            text += f"• Metadata Indicators: {enhanced.get('metadata_density', 0)}\n"
        
        self.enhanced_text.setPlainText(text)

    def export_report(self):
        if not self.analysis_results:
            QMessageBox.warning(self, "Export Error", "No analysis data to export.")
            return
            
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Analysis Report", 
            f"exif_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    # Combine all tab contents
                    tabs_content = [
                        ("OVERVIEW", self.overview_text.toPlainText()),
                        ("EXIF DATA", self.exif_text.toPlainText()),
                        ("CAMERA INFO", self.camera_text.toPlainText()),
                        ("GPS DATA", self.gps_text.toPlainText()),
                        ("FORENSIC ANALYSIS", self.forensic_text.toPlainText()),
                        ("HIDDEN METADATA", self.hidden_text.toPlainText()),
                        ("ENHANCED ANALYSIS", self.enhanced_text.toPlainText())
                    ]
                    
                    for tab_name, content in tabs_content:
                        f.write(f"\n{'='*80}\n")
                        f.write(f"{tab_name}\n")
                        f.write(f"{'='*80}\n\n")
                        f.write(content)
                        f.write("\n\n")
                
                QMessageBox.information(self, "Export Successful", f"Report exported to:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Could not export report:\n{str(e)}")

    def clear_results(self):
        # Clear all text areas
        for text_widget in [self.overview_text, self.exif_text, self.camera_text, 
                          self.gps_text, self.forensic_text, self.hidden_text, self.enhanced_text]:
            text_widget.clear()
        
        # Reset cards
        self.update_dashboard_cards({})
        
        # Clear URL input
        self.url_input.clear()
        
        # Disable export button
        self.btn_export.setEnabled(False)
        self.analysis_results = None
        
        QMessageBox.information(self, "Cleared", "All analysis results have been cleared.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern style
    
    window = AdvancedExifMasterPro()
    window.show()
    
    sys.exit(app.exec_())