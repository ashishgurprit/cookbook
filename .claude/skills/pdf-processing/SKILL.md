---
name: pdf-processing
description: "Production PDF processing pipeline with automatic scanned/digital detection, multi-library text extraction, OCR fallback, and table parsing. Use when: (1) Extracting text from PDFs, (2) Processing invoices or forms, (3) Document digitization pipelines, (4) Table extraction from PDFs, (5) Building document ingestion systems. Triggers on 'PDF processing', 'extract PDF text', 'PDF to text', 'parse PDF', or document extraction requests."
license: Proprietary
---

# PDF Processing Pipeline

Robust PDF processing with automatic detection of scanned vs digital PDFs, multi-library extraction, OCR fallback, and table parsing.

## Quick Reference: PDF Types & Tools

| PDF Type | Detection | Best Tool | Fallback | Quality |
|----------|-----------|-----------|----------|---------|
| **Digital** | Text extractable | PyPDF2/pdfplumber | pdfminer.six | 99% |
| **Scanned** | Image-only | Google Vision OCR | Tesseract | 90-95% |
| **Mixed** | Some pages scanned | Auto-detect per page | Hybrid approach | 95% |
| **Tables** | Structured data | Camelot/Tabula | pdfplumber | 85-90% |
| **Forms** | Fillable fields | PyPDF2 | OCR + parsing | 95% |
| **Images** | Embedded images | PyMuPDF (fitz) | Pillow extraction | 100% |

---

# ARCHITECTURE

## Processing Pipeline

```
PDF File
    │
    ├──► 1. PDF Type Detection
    │        ├─► Check extractable text
    │        ├─► Analyze image DPI
    │        └─► Classify: digital/scanned/mixed
    │
    ├──► 2. Text Extraction Strategy
    │        ├─► Digital PDF → PyPDF2/pdfplumber
    │        ├─► Scanned PDF → OCR (Google Vision/Tesseract)
    │        └─► Mixed PDF → Per-page detection
    │
    ├──► 3. Table Detection & Extraction
    │        ├─► Detect tables (visual analysis)
    │        ├─► Extract with Camelot/Tabula
    │        └─► Validate extracted data
    │
    ├──► 4. Image Extraction (optional)
    │        └─► Extract embedded images
    │
    ├──► 5. Quality Assessment
    │        ├─► Check text confidence
    │        ├─► Validate completeness
    │        └─► Flag low-quality extractions
    │
    ├──► 6. Post-Processing
    │        ├─► Clean text (remove artifacts)
    │        ├─► Preserve structure (headings, lists)
    │        └─► Format output (markdown/JSON)
    │
    └──► Return Results
```

---

# CORE IMPLEMENTATION

## Complete PDF Processor

```python
from typing import Dict, List, Optional
from dataclasses import dataclass
import PyPDF2
import pdfplumber
from PIL import Image
import io

@dataclass
class PDFExtractionResult:
    text: str
    page_count: int
    pdf_type: str  # 'digital', 'scanned', 'mixed'
    tables: List[Dict]
    images: List[Image.Image]
    metadata: Dict
    confidence: float
    extraction_method: str

class PDFProcessor:
    """Production PDF processing with auto-detection"""

    def __init__(self, ocr_provider=None):
        self.ocr_provider = ocr_provider  # Google Vision or Tesseract

    def process(self, pdf_path: str, extract_tables: bool = True, extract_images: bool = False) -> PDFExtractionResult:
        """
        Process PDF with automatic method selection.

        Args:
            pdf_path: Path to PDF file
            extract_tables: Extract tables
            extract_images: Extract embedded images

        Returns:
            PDFExtractionResult with extracted content
        """

        # 1. Detect PDF type
        pdf_type = self.detect_pdf_type(pdf_path)
        print(f"Detected PDF type: {pdf_type}")

        # 2. Extract text
        if pdf_type == 'digital':
            result = self._extract_digital(pdf_path)
        elif pdf_type == 'scanned':
            result = self._extract_scanned(pdf_path)
        else:  # mixed
            result = self._extract_mixed(pdf_path)

        # 3. Extract tables
        if extract_tables:
            result['tables'] = self._extract_tables(pdf_path)

        # 4. Extract images
        if extract_images:
            result['images'] = self._extract_images(pdf_path)

        # 5. Get metadata
        result['metadata'] = self._extract_metadata(pdf_path)

        # 6. Quality assessment
        result['confidence'] = self._assess_quality(result)

        return PDFExtractionResult(**result)

    def detect_pdf_type(self, pdf_path: str) -> str:
        """
        Detect if PDF is digital, scanned, or mixed.

        Strategy:
        - Try extracting text from first page
        - If text found → digital
        - If no text → scanned
        - Check remaining pages for mixed
        """

        try:
            with pdfplumber.open(pdf_path) as pdf:
                total_pages = len(pdf.pages)

                # Check first page
                first_page_text = pdf.pages[0].extract_text()

                if not first_page_text or len(first_page_text.strip()) < 50:
                    # Likely scanned
                    return 'scanned'

                # Check if all pages have text
                pages_with_text = 0
                sample_size = min(5, total_pages)  # Sample first 5 pages

                for i in range(sample_size):
                    text = pdf.pages[i].extract_text()
                    if text and len(text.strip()) > 50:
                        pages_with_text += 1

                if pages_with_text == sample_size:
                    return 'digital'
                elif pages_with_text > 0:
                    return 'mixed'
                else:
                    return 'scanned'

        except Exception as e:
            print(f"Error detecting PDF type: {e}")
            return 'scanned'  # Assume scanned if detection fails

    def _extract_digital(self, pdf_path: str) -> Dict:
        """Extract text from digital PDF"""

        text = []
        page_count = 0

        try:
            with pdfplumber.open(pdf_path) as pdf:
                page_count = len(pdf.pages)

                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text.append(page_text)

            return {
                'text': '\n\n'.join(text),
                'page_count': page_count,
                'pdf_type': 'digital',
                'tables': [],
                'images': [],
                'extraction_method': 'pdfplumber'
            }

        except Exception as e:
            print(f"pdfplumber failed, trying PyPDF2: {e}")
            return self._extract_with_pypdf2(pdf_path)

    def _extract_scanned(self, pdf_path: str) -> Dict:
        """Extract text from scanned PDF using OCR"""

        if not self.ocr_provider:
            raise Exception("OCR provider required for scanned PDFs")

        # Convert PDF pages to images and OCR
        text = []
        page_count = 0

        import pdf2image

        images = pdf2image.convert_from_path(pdf_path)
        page_count = len(images)

        for i, image in enumerate(images):
            print(f"OCR processing page {i+1}/{page_count}...")

            # Save image temporarily
            temp_image_path = f"/tmp/page_{i}.png"
            image.save(temp_image_path)

            # OCR
            ocr_result = self.ocr_provider.process(temp_image_path)

            if ocr_result.success:
                text.append(ocr_result.data['text'])

        return {
            'text': '\n\n'.join(text),
            'page_count': page_count,
            'pdf_type': 'scanned',
            'tables': [],
            'images': [],
            'extraction_method': self.ocr_provider.name
        }

    def _extract_mixed(self, pdf_path: str) -> Dict:
        """Extract from mixed digital/scanned PDF"""

        text = []
        page_count = 0

        with pdfplumber.open(pdf_path) as pdf:
            page_count = len(pdf.pages)

            for i, page in enumerate(pdf.pages):
                # Try digital extraction first
                page_text = page.extract_text()

                if page_text and len(page_text.strip()) > 50:
                    text.append(page_text)
                else:
                    # Fall back to OCR for this page
                    print(f"Page {i+1} appears scanned, using OCR...")

                    if self.ocr_provider:
                        # Convert page to image and OCR
                        import pdf2image
                        images = pdf2image.convert_from_path(pdf_path, first_page=i+1, last_page=i+1)

                        temp_path = f"/tmp/page_{i}.png"
                        images[0].save(temp_path)

                        ocr_result = self.ocr_provider.process(temp_path)
                        if ocr_result.success:
                            text.append(ocr_result.data['text'])

        return {
            'text': '\n\n'.join(text),
            'page_count': page_count,
            'pdf_type': 'mixed',
            'tables': [],
            'images': [],
            'extraction_method': 'hybrid'
        }

    def _extract_tables(self, pdf_path: str) -> List[Dict]:
        """Extract tables using Camelot"""

        try:
            import camelot

            tables = camelot.read_pdf(pdf_path, pages='all')

            extracted_tables = []

            for table in tables:
                extracted_tables.append({
                    'data': table.df.to_dict(),
                    'page': table.page,
                    'accuracy': table.accuracy
                })

            return extracted_tables

        except Exception as e:
            print(f"Table extraction failed: {e}")
            return []

    def _extract_images(self, pdf_path: str) -> List[Image.Image]:
        """Extract embedded images"""

        images = []

        try:
            import fitz  # PyMuPDF

            pdf = fitz.open(pdf_path)

            for page_num in range(len(pdf)):
                page = pdf[page_num]
                image_list = page.get_images()

                for img in image_list:
                    xref = img[0]
                    base_image = pdf.extract_image(xref)
                    image_bytes = base_image["image"]

                    # Convert to PIL Image
                    image = Image.open(io.BytesIO(image_bytes))
                    images.append(image)

        except Exception as e:
            print(f"Image extraction failed: {e}")

        return images

    def _extract_metadata(self, pdf_path: str) -> Dict:
        """Extract PDF metadata"""

        metadata = {}

        try:
            with open(pdf_path, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)

                if pdf.metadata:
                    metadata = {
                        'title': pdf.metadata.get('/Title', ''),
                        'author': pdf.metadata.get('/Author', ''),
                        'subject': pdf.metadata.get('/Subject', ''),
                        'creator': pdf.metadata.get('/Creator', ''),
                        'producer': pdf.metadata.get('/Producer', ''),
                        'creation_date': pdf.metadata.get('/CreationDate', ''),
                    }

        except Exception as e:
            print(f"Metadata extraction failed: {e}")

        return metadata

    def _assess_quality(self, result: Dict) -> float:
        """Assess extraction quality"""

        text = result['text']

        # Basic quality checks
        checks = {
            'has_text': len(text.strip()) > 0,
            'reasonable_length': len(text) > 100,
            'no_excessive_spaces': text.count('  ') / max(len(text), 1) < 0.1,
            'has_alphanumeric': any(c.isalnum() for c in text),
        }

        confidence = sum(checks.values()) / len(checks)

        return confidence

    def _extract_with_pypdf2(self, pdf_path: str) -> Dict:
        """Fallback: PyPDF2 extraction"""

        text = []

        with open(pdf_path, 'rb') as f:
            pdf = PyPDF2.PdfReader(f)

            for page in pdf.pages:
                text.append(page.extract_text())

        return {
            'text': '\n\n'.join(text),
            'page_count': len(pdf.pages),
            'pdf_type': 'digital',
            'tables': [],
            'images': [],
            'extraction_method': 'PyPDF2'
        }
```

---

# ADVANCED FEATURES

## Feature 1: Form Field Extraction

```python
class PDFFormProcessor(PDFProcessor):
    """Extract fillable form fields"""

    def extract_form_fields(self, pdf_path: str) -> Dict:
        """Extract form field values"""

        form_data = {}

        with open(pdf_path, 'rb') as f:
            pdf = PyPDF2.PdfReader(f)

            if '/AcroForm' in pdf.trailer['/Root']:
                fields = pdf.get_fields()

                for field_name, field_value in fields.items():
                    form_data[field_name] = field_value.get('/V', '')

        return form_data
```

## Feature 2: Invoice Parsing

```python
class InvoiceProcessor(PDFProcessor):
    """Specialized invoice/receipt processing"""

    def extract_invoice_data(self, pdf_path: str) -> Dict:
        """Extract structured invoice data"""

        result = self.process(pdf_path, extract_tables=True)

        # Use regex to find common invoice fields
        import re

        text = result.text

        invoice_data = {
            'invoice_number': self._extract_pattern(text, r'Invoice\s*#?:?\s*(\S+)'),
            'date': self._extract_pattern(text, r'Date:?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})'),
            'total': self._extract_pattern(text, r'Total:?\s*\$?([\d,]+\.?\d*)'),
            'vendor': self._extract_pattern(text, r'From:?\s*([^\n]+)'),
            'customer': self._extract_pattern(text, r'To:?\s*([^\n]+)'),
        }

        # Extract line items from tables
        if result.tables:
            invoice_data['line_items'] = result.tables[0]['data']

        return invoice_data

    def _extract_pattern(self, text: str, pattern: str) -> Optional[str]:
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1) if match else None
```

## Feature 3: Multi-PDF Batch Processing

```python
from pathlib import Path

class BatchPDFProcessor:
    """Process multiple PDFs efficiently"""

    def __init__(self):
        self.processor = PDFProcessor()

    def process_directory(self, directory: str, output_format: str = 'json') -> List[Dict]:
        """Process all PDFs in directory"""

        pdf_files = list(Path(directory).glob('*.pdf'))
        results = []

        for pdf_file in pdf_files:
            print(f"Processing {pdf_file.name}...")

            try:
                result = self.processor.process(str(pdf_file))

                output = {
                    'filename': pdf_file.name,
                    'text': result.text,
                    'page_count': result.page_count,
                    'confidence': result.confidence,
                    'metadata': result.metadata
                }

                results.append(output)

                # Save individual result
                if output_format == 'json':
                    import json
                    output_path = pdf_file.with_suffix('.json')
                    with open(output_path, 'w') as f:
                        json.dump(output, f, indent=2)

            except Exception as e:
                print(f"Failed to process {pdf_file.name}: {e}")

        return results
```

---

# BEST PRACTICES

## 1. Choosing Extraction Method

```python
# Decision tree
if pdf_has_extractable_text():
    use_pdfplumber()  # Best for digital PDFs
elif pdf_is_high_quality_scan():
    use_google_vision_ocr()  # Best accuracy
elif pdf_is_low_quality_scan():
    use_tesseract_with_preprocessing()  # Free, decent accuracy
else:
    use_hybrid_approach()  # Per-page detection
```

## 2. Handling Large PDFs

```python
# Process in chunks
def process_large_pdf(pdf_path: str, chunk_size: int = 10):
    """Process large PDF in chunks"""

    total_pages = get_page_count(pdf_path)

    for start in range(0, total_pages, chunk_size):
        end = min(start + chunk_size, total_pages)

        # Process chunk
        chunk_text = extract_pages(pdf_path, start, end)

        # Yield results incrementally
        yield {
            'pages': f"{start+1}-{end}",
            'text': chunk_text
        }
```

## 3. Quality Thresholds

```python
# Set quality thresholds
CONFIDENCE_THRESHOLDS = {
    'high': 0.95,      # Use directly
    'medium': 0.80,    # Review recommended
    'low': 0.60,       # Manual review required
}

if result.confidence > CONFIDENCE_THRESHOLDS['high']:
    use_automatically()
elif result.confidence > CONFIDENCE_THRESHOLDS['medium']:
    flag_for_review()
else:
    manual_processing_required()
```

---

# REAL-WORLD EXAMPLE

## Document Ingestion Pipeline

```python
# See examples/document-pipeline.py

from pdf_processor import PDFProcessor, BatchPDFProcessor
from ocr_provider import GoogleVisionProvider

# Initialize
ocr = GoogleVisionProvider(config={'api_key': 'YOUR_KEY'})
processor = PDFProcessor(ocr_provider=ocr)

# Process single PDF
result = processor.process('invoice.pdf', extract_tables=True)

print(f"Extracted {len(result.text)} characters")
print(f"Found {len(result.tables)} tables")
print(f"Confidence: {result.confidence:.2%}")

# Batch process directory
batch_processor = BatchPDFProcessor()
results = batch_processor.process_directory('./documents/', output_format='json')

print(f"Processed {len(results)} documents")
```

---

# FILE REFERENCES

- `templates/pdf_processor.py` - Complete PDF processor class
- `templates/ocr_provider.py` - OCR provider integrations
- `templates/quality_assessor.py` - Quality scoring system
- `templates/table_extractor.py` - Table extraction utilities
- `checklists/pdf-processing.md` - Processing checklist
- `examples/invoice-extraction.py` - Invoice parsing example
- `examples/form-processing.py` - Form field extraction
- `references/ocr-provider-guide.md` - OCR provider comparison
- `references/pdf-libraries.md` - Python PDF library comparison

## Integrates With

| Module | Path | Description |
|--------|------|-------------|
| document-extractor | modules/document-extractor/ | Document text extraction backend — PDF, DOCX, HTML parsing, table extraction, OCR fallback |
