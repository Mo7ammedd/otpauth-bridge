use std::io::Cursor;

use image::{DynamicImage, ImageFormat, Luma};
use otpauth_bridge::{
    formats::{self, InputFormat},
    qr,
};

#[test]
fn exported_qr_is_decodable_and_preserves_every_account_parameter() {
    let accounts = formats::import(
        include_bytes!("fixtures/accounts.txt"),
        InputFormat::Auto,
        None,
    )
    .unwrap();
    for account in accounts {
        let uri = formats::otpauth::encode(&account).unwrap();
        let png = qr::encode(&uri).unwrap();
        assert!(png.starts_with(b"\x89PNG"));
        let decoded = formats::import(&png, InputFormat::Auto, None).unwrap();
        assert_eq!(decoded, vec![account]);
    }
}

#[test]
fn decodes_multiple_qr_codes_in_one_image() {
    let accounts = formats::import(
        include_bytes!("fixtures/accounts.txt"),
        InputFormat::Auto,
        None,
    )
    .unwrap();
    let images: Vec<_> = accounts
        .iter()
        .map(|account| {
            let png = qr::encode(&formats::otpauth::encode(account).unwrap()).unwrap();
            image::load_from_memory(&png).unwrap().to_luma8()
        })
        .collect();
    let mut combined = image::GrayImage::from_pixel(
        images[0].width() + images[1].width() + 64,
        images.iter().map(|img| img.height()).max().unwrap(),
        Luma([255]),
    );
    image::imageops::replace(&mut combined, &images[0], 0, 0);
    image::imageops::replace(
        &mut combined,
        &images[1],
        i64::from(images[0].width()) + 64,
        0,
    );
    let mut bytes = Cursor::new(Vec::new());
    DynamicImage::ImageLuma8(combined)
        .write_to(&mut bytes, ImageFormat::Png)
        .unwrap();
    let decoded = formats::import(bytes.get_ref(), InputFormat::Auto, None).unwrap();
    assert_eq!(decoded.len(), 2);
    for account in accounts {
        assert!(decoded.contains(&account));
    }
}

#[test]
fn jpeg_qr_images_are_supported() {
    let uri = "otpauth://totp/Test:alice?secret=JBSWY3DPEHPK3PXP&issuer=Test";
    let png = qr::encode(uri).unwrap();
    let image = image::load_from_memory(&png).unwrap();
    let mut jpeg = Cursor::new(Vec::new());
    image.write_to(&mut jpeg, ImageFormat::Jpeg).unwrap();
    assert_eq!(qr::decode(jpeg.get_ref()).unwrap()[0].as_str(), uri);
}

#[test]
fn empty_and_damaged_images_fail() {
    assert!(qr::decode(b"\x89PNG\r\n\x1a\ncorrupt").is_err());
    let blank = DynamicImage::ImageLuma8(image::GrayImage::from_pixel(128, 128, Luma([255])));
    let mut bytes = Cursor::new(Vec::new());
    blank.write_to(&mut bytes, ImageFormat::Png).unwrap();
    assert!(
        qr::decode(bytes.get_ref())
            .unwrap_err()
            .to_string()
            .contains("no QR code")
    );
}
