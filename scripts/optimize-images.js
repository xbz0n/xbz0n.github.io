const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

const IMAGES_DIR = path.join(__dirname, '../public/images');
const ORIGINALS_DIR = path.join(IMAGES_DIR, 'originals');
const MAX_WIDTH = 1200;
const JPEG_QUALITY = 85;
const PNG_QUALITY = 90;

// Image extensions to process
const IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png'];

async function optimizeImages() {
  console.log('🖼️  Image Optimization Script\n');

  // Create originals directory if it doesn't exist
  if (!fs.existsSync(ORIGINALS_DIR)) {
    fs.mkdirSync(ORIGINALS_DIR, { recursive: true });
    console.log('✅ Created backup directory: public/images/originals/\n');
  }

  // Get all image files
  const files = fs.readdirSync(IMAGES_DIR)
    .filter(file => {
      const ext = path.extname(file).toLowerCase();
      return IMAGE_EXTENSIONS.includes(ext) && fs.statSync(path.join(IMAGES_DIR, file)).isFile();
    });

  if (files.length === 0) {
    console.log('❌ No images found to optimize');
    return;
  }

  console.log(`📁 Found ${files.length} images to optimize\n`);

  let totalSizeBefore = 0;
  let totalSizeAfter = 0;

  for (const file of files) {
    const filePath = path.join(IMAGES_DIR, file);
    const originalPath = path.join(ORIGINALS_DIR, file);
    const ext = path.extname(file).toLowerCase();

    // Get original size
    const statsBefore = fs.statSync(filePath);
    const sizeBefore = statsBefore.size;
    totalSizeBefore += sizeBefore;

    // Skip if already backed up
    if (!fs.existsSync(originalPath)) {
      // Copy to originals folder as backup
      fs.copyFileSync(filePath, originalPath);
    }

    try {
      // Load image
      const image = sharp(filePath);
      const metadata = await image.metadata();

      // Prepare optimization pipeline
      let pipeline = sharp(filePath);

      // Resize if too large
      if (metadata.width > MAX_WIDTH) {
        pipeline = pipeline.resize(MAX_WIDTH, null, {
          fit: 'inside',
          withoutEnlargement: true
        });
      }

      // Optimize based on format
      if (ext === '.png') {
        await pipeline
          .png({ quality: PNG_QUALITY, compressionLevel: 9 })
          .toFile(filePath + '.tmp');
      } else if (ext === '.jpg' || ext === '.jpeg') {
        await pipeline
          .jpeg({ quality: JPEG_QUALITY, progressive: true, mozjpeg: true })
          .toFile(filePath + '.tmp');
      }

      // Replace original with optimized
      fs.renameSync(filePath + '.tmp', filePath);

      // Get new size
      const statsAfter = fs.statSync(filePath);
      const sizeAfter = statsAfter.size;
      totalSizeAfter += sizeAfter;

      // Calculate savings
      const savings = ((sizeBefore - sizeAfter) / sizeBefore * 100).toFixed(1);
      const beforeKB = (sizeBefore / 1024).toFixed(1);
      const afterKB = (sizeAfter / 1024).toFixed(1);

      console.log(`✅ ${file}`);
      console.log(`   ${beforeKB}KB → ${afterKB}KB (${savings}% smaller)`);
      if (metadata.width > MAX_WIDTH) {
        console.log(`   Resized from ${metadata.width}px to ${MAX_WIDTH}px width`);
      }
      console.log();

    } catch (error) {
      console.error(`❌ Error optimizing ${file}:`, error.message);
    }
  }

  // Summary
  const totalSavings = ((totalSizeBefore - totalSizeAfter) / totalSizeBefore * 100).toFixed(1);
  const totalBeforeKB = (totalSizeBefore / 1024).toFixed(1);
  const totalAfterKB = (totalSizeAfter / 1024).toFixed(1);
  const savedKB = (totalBeforeKB - totalAfterKB).toFixed(1);

  console.log('═══════════════════════════════════════');
  console.log('📊 OPTIMIZATION SUMMARY');
  console.log('═══════════════════════════════════════');
  console.log(`Total files processed: ${files.length}`);
  console.log(`Total size before: ${totalBeforeKB}KB`);
  console.log(`Total size after: ${totalAfterKB}KB`);
  console.log(`Total saved: ${savedKB}KB (${totalSavings}%)`);
  console.log(`\n✅ Originals backed up to: public/images/originals/`);
}

optimizeImages().catch(console.error);
