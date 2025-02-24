import cv2
import numpy as np
import argparse

def generate_video(output_path, duration=10, resolution=(1280, 720), color=(0, 0, 255)):
    fps = 30
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(output_path, fourcc, fps, resolution)

    for _ in range(fps * duration):
        frame = np.full((resolution[1], resolution[0], 3), color, dtype=np.uint8)
        out.write(frame)

    out.release()
    print(f"✅ Background video generated: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a simple background video.")
    parser.add_argument("--output", required=True, help="Output video file path")
    args = parser.parse_args()

    generate_video(args.output)
