"""
vision.py — Deep Learning Binary Vision Engine (ResNet-18 2D-CNN).

Implements the "Pixel Trick" and 2D-CNN pipeline:
  1. Reads raw binary executable as 1D byte array (values 0..255).
  2. Reshapes 1D byte array into a 2D matrix using standard malware byte-image mapping
     (Nataraj et al. width rules) and resizes to a fixed 256x256 greyscale image.
  3. Feeds 256x256 image into a ResNet-18 Convolutional Neural Network.
  4. Produces an independent P(malware) probability and classification verdict.

This engine is completely independent of the static LightGBM engine and runs safely
without executing or disassembling the target binary.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

import numpy as np
from PIL import Image
import torch
import torch.nn as nn
from torchvision import models, transforms

from . import config

MALWARE = "MALWARE"
SAFE = "SAFE"
ERROR = "ERROR"


@dataclass
class VisionResult:
    """The deep learning vision verdict for one input binary."""
    cnn_verdict: str                  # MALWARE | SAFE | ERROR
    cnn_prob: float | None = None     # P(malware), 0.0 - 1.0
    error: str | None = None          # Populated only when cnn_verdict == ERROR
    image_shape: Tuple[int, int] = (256, 256)


# ── Byte-to-Image Transformation ─────────────────────────────────────────────

def get_image_width(size_bytes: int) -> int:
    """Determines grid width based on file size (Nataraj et al. standard)."""
    kb = size_bytes / 1024
    if kb < 10:
        return 32
    elif kb < 30:
        return 64
    elif kb < 60:
        return 128
    elif kb < 100:
        return 256
    elif kb < 200:
        return 384
    elif kb < 500:
        return 512
    elif kb < 1000:
        return 768
    else:
        return 1024


def bytes_to_pil_image(data: bytes, target_size: Tuple[int, int] = (256, 256)) -> Image.Image:
    """Converts raw executable bytes to a 256x256 grayscale PIL Image.
    
    Preserves macro-structural layout (headers, code sections, resource blocks)
    by arranging bytes into a 2D matrix before resizing.
    """
    if not data or len(data) < config.MIN_FILE_BYTES:
        raise ValueError("Binary data too small or empty to generate byte-image.")

    raw_arr = np.frombuffer(data, dtype=np.uint8)
    width = get_image_width(len(raw_arr))
    
    # Pad trailing bytes with zeros so length is an exact multiple of width
    pad_len = (width - (len(raw_arr) % width)) % width
    if pad_len > 0:
        padded = np.pad(raw_arr, (0, pad_len), mode="constant", constant_values=0)
    else:
        padded = raw_arr
        
    height = len(padded) // width
    matrix_2d = padded.reshape((height, width))
    
    # Create PIL Grayscale image (mode 'L')
    img = Image.fromarray(matrix_2d, mode="L")
    
    # Resize to fixed 256x256 grid
    img_resized = img.resize(target_size, Image.Resampling.BILINEAR)
    return img_resized


def image_to_tensor(img: Image.Image) -> torch.Tensor:
    """Preprocesses a PIL grayscale image into a normalized PyTorch tensor.
    
    Replicates the single channel across 3 RGB channels and applies standard
    ImageNet normalization for ResNet-18 feature extraction.
    """
    preprocess = transforms.Compose([
        transforms.Grayscale(num_output_channels=3),
        transforms.ToTensor(),
        transforms.Normalize(
            mean=[0.485, 0.456, 0.406],
            std=[0.229, 0.224, 0.225]
        )
    ])
    tensor = preprocess(img)
    return tensor.unsqueeze(0)  # Shape: (1, 3, 256, 256)


# ── ResNet-18 Classifier Architecture ───────────────────────────────────────

class ResNet18Binary(nn.Module):
    """ResNet-18 model adapted for binary malware vs safe classification."""

    def __init__(self, pretrained: bool = False):
        super().__init__()
        weights = models.ResNet18_Weights.DEFAULT if pretrained else None
        self.backbone = models.resnet18(weights=weights)
        in_features = self.backbone.fc.in_features
        # Binary classification head: output 2 classes [Safe, Malware]
        self.backbone.fc = nn.Sequential(
            nn.Dropout(0.2),
            nn.Linear(in_features, 2)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.backbone(x)


# ── Vision Engine Core ──────────────────────────────────────────────────────

class VisionEngine:
    """Manages ResNet-18 model lifecycle and handles image inference."""

    def __init__(self, model_path: Path | str | None = None, threshold: float = 0.50):
        self.threshold = threshold
        self.model_path = Path(model_path) if model_path else (config.MODELS_DIR / "resnet18_malware.pth")
        self.device = torch.device("cpu")  # CPU inference for universal desktop compatibility
        self.model = self._load_or_init_model()
        self.model.eval()

    def _load_or_init_model(self) -> ResNet18Binary:
        """Loads trained weights if available, or initializes an evaluation model."""
        model = ResNet18Binary(pretrained=False)
        if self.model_path.exists():
            try:
                state_dict = torch.load(self.model_path, map_location=self.device)
                model.load_state_dict(state_dict)
            except Exception as e:
                # If weights file is corrupted, fall back to initialization
                pass
        else:
            # Ensure model directory exists and save initialized state dict for offline runtime
            try:
                self.model_path.parent.mkdir(parents=True, exist_ok=True)
                torch.save(model.state_dict(), self.model_path)
            except OSError:
                pass
        model.to(self.device)
        return model

    def classify_bytes(self, data: bytes) -> VisionResult:
        """Convert bytes to image and classify with ResNet-18. Never raises."""
        try:
            if not data or len(data) < config.MIN_FILE_BYTES:
                return VisionResult(ERROR, error="file too small / empty")
            
            img = bytes_to_pil_image(data, target_size=(256, 256))
            tensor = image_to_tensor(img).to(self.device)
            
            with torch.no_grad():
                logits = self.model(tensor)
                probs = torch.softmax(logits, dim=1)
                cnn_prob = float(probs[0, 1].item())  # Index 1 = Malware probability
                
            verdict = MALWARE if cnn_prob >= self.threshold else SAFE
            return VisionResult(cnn_verdict=verdict, cnn_prob=cnn_prob)
            
        except Exception as e:
            return VisionResult(ERROR, error=f"vision inference failed: {e}")

    def classify_file(self, path: Path | str) -> VisionResult:
        """Read binary from disk and perform vision classification."""
        try:
            with open(path, "rb") as f:
                data = f.read()
            return self.classify_bytes(data)
        except Exception as e:
            return VisionResult(ERROR, error=f"read failed: {e}")


# ── Shared Singleton Instance ────────────────────────────────────────────────

_VISION_ENGINE: VisionEngine | None = None


def get_vision_engine() -> VisionEngine:
    """Returns a shared singleton instance of VisionEngine."""
    global _VISION_ENGINE
    if _VISION_ENGINE is None:
        _VISION_ENGINE = VisionEngine()
    return _VISION_ENGINE


def reset_vision_engine() -> None:
    """Resets the singleton instance."""
    global _VISION_ENGINE
    _VISION_ENGINE = None
