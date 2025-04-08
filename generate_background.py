import os
import sys
import webbrowser
import cv2
import ffmpeg
import codecs
import argparse
import logging

# Ensure UTF-8 encoding for output
sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

def ensure_file_exists(file_path):
    """Ensure the given file exists, otherwise warn the user."""
    if not os.path.exists(file_path):
        logger.error(f"⚠️ Warning: {file_path} not found. Please provide a valid video file.")
        sys.exit(1)

def process_video(input_video, text, output, format, font_style, text_position, music_file=None):
    """Overlay text on an existing video and optionally add background music."""
    try:
        ensure_file_exists(input_video)  # Check if input video exists

        # Ensure the output directory exists
        output_dir = os.path.dirname(output)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)

        output_file = f"{output}.{format}"

        cap = cv2.VideoCapture(input_video)
        if not cap.isOpened():
            logger.error(f"❌ Error: Cannot open input video {input_video}.")
            sys.exit(1)

        # Get video properties
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = int(cap.get(cv2.CAP_PROP_FPS))
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

        if width == 0 or height == 0 or fps == 0:
            logger.error("❌ Error: Invalid video file. Check file integrity.")
            sys.exit(1)

        logger.info(f"📹 Video Details: {width}x{height} @ {fps} FPS, {frame_count} frames")

        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        video_writer = cv2.VideoWriter(output_file, fourcc, fps, (width, height))

        # Define the font style
        if font_style == "bold":
            font = cv2.FONT_HERSHEY_DUPLEX  # Bold font style
        elif font_style == "italic":
            font = cv2.FONT_HERSHEY_SIMPLEX  # Simple font, italic effect can be simulated by slanting text (but OpenCV doesn't support italic directly)
        else:
            font = cv2.FONT_HERSHEY_SIMPLEX  # Default font

        font_scale = 1
        font_thickness = 2
        text_size = cv2.getTextSize(text, font, font_scale, font_thickness)[0]
        
        # Handle text position customization
        if text_position == "center":
            text_x = (width - text_size[0]) // 2
            text_y = height - 50
        elif text_position == "top-left":
            text_x = 10
            text_y = 30
        elif text_position == "bottom-left":
            text_x = 10
            text_y = height - 50
        elif text_position == "top-right":
            text_x = width - text_size[0] - 10
            text_y = 30
        elif text_position == "bottom-right":
            text_x = width - text_size[0] - 10
            text_y = height - 50

        processed_frames = 0
        while True:
            ret, frame = cap.read()
            if not ret:
                break  # End of video

            if frame is None:
                logger.warning(f"⚠️ Skipping empty frame {processed_frames + 1}")
                continue

            cv2.putText(frame, text, (text_x, text_y), font, font_scale, (255, 255, 255), font_thickness, cv2.LINE_AA)
            video_writer.write(frame)
            processed_frames += 1

        cap.release()
        video_writer.release()

        if processed_frames == 0:
            logger.error("❌ Error: No frames were processed. Video might be corrupted.")
            sys.exit(1)

        logger.info(f"✅ Video processing complete: {output_file}")

        # Add background music if available
        if music_file and os.path.exists(music_file):
            temp_output = f"{output}_temp.{format}"
            try:
                ffmpeg.input(output_file).input(music_file).output(
                    temp_output, vcodec="libx264", acodec="aac", shortest=None
                ).run(overwrite_output=True)
                os.replace(temp_output, output_file)
                logger.info("🎵 Background music added successfully!")
            except Exception as e:
                logger.warning(f"⚠️ Warning: Could not add background music: {e}")
        elif music_file:
            logger.warning(f"⚠️ Music file {music_file} not found. Skipping music addition.")

        # Open the generated video in the default web browser
        webbrowser.open(f"file://{os.path.abspath(output_file)}")

        return output_file
    except Exception as e:
        logger.error(f"❌ Error processing video: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Overlay text on a video.")
    parser.add_argument("--text", required=True, help="Text to overlay on the video")
    parser.add_argument("--input", required=True, help="Path to the input video file")
    parser.add_argument("--output", required=True, help="Output video file name (without extension)")
    parser.add_argument("--format", default="mp4", choices=["mp4", "avi", "mov"], help="Video format")
    parser.add_argument("--font", default="simple", choices=["simple", "bold", "italic"], help="Font style")
    parser.add_argument("--position", default="center", choices=["center", "top-left", "bottom-left", "top-right", "bottom-right"], help="Text position")
    parser.add_argument("--music", help="Path to background music file (optional)")

    args = parser.parse_args()

    video_path = process_video(args.input, args.text, args.output, args.format, args.font, args.position, args.music)
    logger.info(f"📂 Output saved at: {video_path}")
