from PIL import Image
import piexif
import os

def remove_metadata(input_path, output_path=None):
    try:
        image = Image.open(input_path)
        data = list(image.getdata())
        image_no_exif = Image.new(image.mode, image.size)
        image_no_exif.putdata(data)

        if not output_path:
            output_path = f"cleaned_{os.path.basename(input_path)}"

        image_no_exif.save(output_path)
        print(f"✅ Metadata removed! Saved as {output_path}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    file_path = input("Enter image file path: ")
    remove_metadata(file_path)
