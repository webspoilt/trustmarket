const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

const svgPath = path.join(__dirname, 'public', 'favicon.svg');
const publicDir = path.join(__dirname, 'public');

async function generateIcons() {
    try {
        const svgBuffer = fs.readFileSync(svgPath);

        // 192x192 PNG for Android PWA
        await sharp(svgBuffer)
            .resize(192, 192)
            .png()
            .toFile(path.join(publicDir, 'logo192.png'));

        // 512x512 PNG for Android PWA splash
        await sharp(svgBuffer)
            .resize(512, 512)
            .png()
            .toFile(path.join(publicDir, 'logo512.png'));

        // 180x180 PNG for Apple Touch Icon
        await sharp(svgBuffer)
            .resize(180, 180)
            .png()
            .toFile(path.join(publicDir, 'apple-touch-icon.png'));

        // 64x64 PNG mapped to favicon.ico (Browsers support PNG masquerading as ICO, but true ICO needs a different package. We'll use 64x64 PNG for now to replace the default CRA icon)
        await sharp(svgBuffer)
            .resize(64, 64)
            .png()
            .toFile(path.join(publicDir, 'favicon.ico'));

        console.log('✅ Successfully generated all TrustMarket logomark variations (192, 512, 180, 64)!');
    } catch (error) {
        console.error('Failed to generate icons:', error);
    }
}

generateIcons();
