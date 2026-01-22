use std::io::Write;

use anyhow::Result;
use image::GenericImageView;
use tempfile::NamedTempFile;

/// Display profile picture in terminal using different methods
pub struct ImageDisplay;

impl ImageDisplay {
    /// Display image using viuer (terminal image display)
    pub async fn display_with_viuer(image_url: &str) -> Result<()> {
        // Download image to temporary file
        let response = reqwest::get(image_url).await?;
        let image_data = response.bytes().await?;

        // Create temporary file
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(&image_data)?;
        temp_file.flush()?;

        // Display with viuer
        let conf = viuer::Config {
            width: Some(50),
            height: Some(50),
            ..Default::default()
        };

        viuer::print_from_file(temp_file.path(), &conf)?;
        Ok(())
    }

    /// Display image as colored block art
    pub async fn display_as_ascii(image_url: &str) -> Result<()> {
        // Download image
        let response = reqwest::get(image_url).await?;
        let image_data = response.bytes().await?;

        // Load image
        let img = image::load_from_memory(&image_data)?;

        // Calculate aspect ratio based on terminal line spacing
        let (width, height) = Self::calculate_display_size();
        let resized = img.resize(width, height, image::imageops::FilterType::Lanczos3);

        // Unicode block characters
        let block_chars = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

        println!("\n🖼️  Profile Picture (Colored Block Art):");
        println!("{}", "─".repeat(50));

        for y in 0..resized.height() {
            for x in 0..resized.width() {
                let pixel = resized.get_pixel(x, y);
                let r = pixel[0];
                let g = pixel[1];
                let b = pixel[2];

                // Convert to grayscale for character selection
                let gray_value = (r as f32 * 0.299 + g as f32 * 0.587 + b as f32 * 0.114) / 255.0;
                let char_index = (gray_value * (block_chars.len() - 1) as f32) as usize;
                let char = block_chars[char_index];

                // Apply color based on RGB values
                let color_code = Self::rgb_to_ansi_color(r, g, b);
                print!("\x1b[{}m{}", color_code, char);
            }
            println!();
        }

        // Reset color and add separator
        print!("\x1b[0m");
        println!("{}", "─".repeat(50));
        Ok(())
    }

    /// Calculate display size based on terminal line spacing
    fn calculate_display_size() -> (u32, u32) {
        // Use default display size

        // Fixed dimensions for optimal display (increased by 30%)
        let width = 56; // Increased by 30% (43 * 1.3)
        let height = 16; // Increased by 30% (12 * 1.3)
        (width, height)
    }

    /// Convert RGB values to ANSI color code
    fn rgb_to_ansi_color(r: u8, g: u8, b: u8) -> u8 {
        // Use a simpler 8-color palette for better compatibility
        let brightness = (r as f32 * 0.299 + g as f32 * 0.587 + b as f32 * 0.114) / 255.0;

        if brightness < 0.1 {
            0 // Black
        } else if brightness < 0.3 {
            if r > g && r > b {
                31
            } else if g > r && g > b {
                32
            } else if b > r && b > g {
                34
            } else {
                30
            }
        } else if brightness < 0.5 {
            if r > g && r > b {
                91
            } else if g > r && g > b {
                92
            } else if b > r && b > g {
                94
            } else {
                90
            }
        } else if brightness < 0.7 {
            if r > g && r > b {
                33
            } else if g > r && g > b {
                93
            } else if b > r && b > g {
                96
            } else {
                37
            }
        } else if brightness < 0.9 {
            if r > g && r > b {
                95
            } else if g > r && g > b {
                97
            } else if b > r && b > g {
                96
            } else {
                97
            }
        } else {
            97 // White
        }
    }

    /// Smart display - show colored block art only
    pub async fn smart_display(image_url: &str) -> Result<()> {
        // Try colored block art display
        match Self::display_as_ascii(image_url).await {
            Ok(_) => {
                println!("✅ Colored block art displayed successfully!");
            }
            Err(e) => {
                println!("❌ Colored block art failed: {}. Showing URL only.", e);
            }
        }

        Ok(())
    }
}
