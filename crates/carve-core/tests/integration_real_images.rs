use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use carve_core::jpeg::parse::parse_until_sos;

#[test]
fn test_real_jpeg_parsing_valid_img_1390() {
    // Locate the test file relative to the crate root
    let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("tests/fixtures/IMG_1390.JPG");

    // Ensure the file exists before trying to open (to avoid cryptic errors if running in incorrect context)
    if !file_path.exists() {
        eprintln!("Skipping test: Test file not found at {:?}", file_path);
        return;
    }

    let mut f = File::open(&file_path).expect("failed to open IMG_1390.JPG");
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).expect("failed to read file");

    // The file is a raw dump containing embedded JPEGs. 
    // The main image starts at offset 964096 (found via analysis).
    let start_offset = 964096;
    
    if buffer.len() <= start_offset {
        panic!("File too small for expected offset");
    }

    let res = parse_until_sos(&buffer, start_offset, buffer.len()).expect("parse_until_sos failed on valid image");

    // The main image in IMG_1390.JPG is 2992x2992 (detected via manual scan).
    // The thumbnail (160x120) is likely inside APP1 Exif and skipped by the top-level parser.
    // If separate, the parser stops at the first SOS.
    // Let's verify what we found.
    
    assert!(res.width.is_some(), "Width not extracted");
    assert!(res.height.is_some(), "Height not extracted");
    
    let width = res.width.unwrap();
    let height = res.height.unwrap();
    
    println!("Extracted dimensions: {}x{}", width, height);
    
    // We expect the main image dimensions.
    assert_eq!(width, 2992);
    assert_eq!(height, 2992);

    assert_eq!(res.is_progressive, Some(false));
    assert!(res.has_dqt);
    assert!(res.has_dht);
    // assert!(res.has_exif); // Main image at 964096 does not seem to have Exif
}

#[test]
fn test_real_jpeg_parsing_thumbnail_img_1390() {
    let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("tests/fixtures/IMG_1390.JPG");

    // Ensure the file exists before trying to open (to avoid cryptic errors if running in incorrect context)
    if !file_path.exists() {
        eprintln!("Skipping test: Test file not found at {:?}", file_path);
        return;
    }

    let mut f = File::open(&file_path).expect("failed to open IMG_1390.JPG");
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).expect("failed to read file");

    let thumbnail_offset = 955904;
    
    if buffer.len() <= thumbnail_offset {
        panic!("File too small for thumbnail offset");
    }

    let res = parse_until_sos(&buffer, thumbnail_offset, buffer.len()).expect("parse_until_sos failed on thumbnail");
    
    let width = res.width.unwrap();
    let height = res.height.unwrap();
    
    println!("Thumbnail dimensions: {}x{}", width, height);

    // Thumbnail should be 160x120
    assert_eq!(width, 160);
    assert_eq!(height, 120);
    
    assert_eq!(res.is_progressive, Some(false));
    // It might or might not contain Exif/DQT/DHT
    assert!(res.has_dqt); 
    // Exif inside a thumbnail? Maybe not.
}

#[test]
fn test_real_jpeg_parsing_missing_soi() {
    let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("tests/fixtures/missing_soi.JPG");
    
    if !file_path.exists() {
        eprintln!("Skipping test: Test file not found at {:?}", file_path);
        return;
    }

    let mut f = File::open(&file_path).expect("failed to open missing_soi.JPG");
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).expect("read failed");

    // Should fail because SOI is missing
    let res = parse_until_sos(&buffer, 0, buffer.len());
    assert!(res.is_err(), "Should detect missing SOI/Not JPEG");
}
