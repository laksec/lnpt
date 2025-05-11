### 7.3 Metadata Analysis
    :- Extract EXIF data from an image
    exiftool image.jpg -o exif_metadata.txt
    
    :- Extract common metadata from PDFs in a folder
    exiftool -r -ext pdf -common documents_folder/ -csv > metadata_report.csv 
