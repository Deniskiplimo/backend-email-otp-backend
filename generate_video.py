import argparse
import os
import sys
import webbrowser
import cv2
import ffmpeg

def process_video(input_video, text, output, format):
    """Overlay text on an existing video."""
    try:
        if os.path.dirname(output):  # Only create if a directory is specified
            os.makedirs(os.path.dirname(output), exist_ok=True)

        output_file = f"{output}.{format}"

        cap = cv2.VideoCapture(input_video)
        if not cap.isOpened():
            print(f"❌ Error: Cannot open input video {input_video}.", file=sys.stderr)
            sys.exit(1)

        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = int(cap.get(cv2.CAP_PROP_FPS))

        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        video_writer = cv2.VideoWriter(output_file, fourcc, fps, (width, height))

        font = cv2.FONT_HERSHEY_SIMPLEX
        font_scale = 1
        font_thickness = 2
        text_size = cv2.getTextSize(text, font, font_scale, font_thickness)[0]
        text_x = (width - text_size[0]) // 2
        text_y = height - 50  # Position near the bottom

        while True:
            ret, frame = cap.read()
            if not ret:
                break  # End of video

            cv2.putText(frame, text, (text_x, text_y), font, font_scale, (255, 255, 255), font_thickness, cv2.LINE_AA)
            video_writer.write(frame)

        cap.release()
        video_writer.release()

        # Add background music if available
        music_file = "background.mp3"
        if os.path.exists(music_file):
            temp_output = f"{output}_temp.{format}"
            ffmpeg.input(output_file).output(temp_output, vcodec="copy", acodec="aac", shortest=None).run(overwrite_output=True)
            os.replace(temp_output, output_file)

        webbrowser.open(f"file://{os.path.abspath(output_file)}")

        return output_file
    except Exception as e:
        print(f"❌ Error processing video: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Overlay text on a video of running dogs.")
    parser.add_argument("--text", required=True, help="Text to overlay on the video")
    parser.add_argument("--input", required=True, help="Path to the input video file")
    parser.add_argument("--output", required=True, help="Output video file name (without extension)")
    parser.add_argument("--format", default="mp4", choices=["mp4", "avi", "mov"], help="Video format")

    args = parser.parse_args()
    
    video_path = process_video(args.input, args.text, args.output, args.format)
    print(video_path)
