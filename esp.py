#!/usr/bin/env python3
"""
Production-ready external box ESP for MECCHA CHAMELEON (UE5.6).
Fully external: scans GUObjectArray, walks objects, renders overlay.
"""
import sys
import os
import json
import struct
import math
import ctypes
import time
from dataclasses import dataclass, asdict, fields
from typing import Tuple

import pymem
from PyQt5.QtWidgets import (
    QApplication, QWidget, QCheckBox, QComboBox, QLabel,
    QVBoxLayout, QHBoxLayout, QPushButton, QFrame, QColorDialog,
    QSlider
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPainter, QPen, QColor, QFont


# ---------------------------------------------------------------------------
# Bootstrap offsets: stable UObject/UStruct/FField layout used to resolve
# everything else dynamically at runtime.
# ---------------------------------------------------------------------------
OFFSETS = {
    "UObjectBase::ClassPrivate": 0x10,
    "UObjectBase::NamePrivate": 0x18,
    "UObjectBase::OuterPrivate": 0x20,

    "UStruct::SuperStruct": 0x40,
    "UStruct::ChildProperties": 0x50,

    "FField::Next": 0x18,
    "FField::NamePrivate": 0x20,
    "FProperty::Offset_Internal": 0x44,

    # Nested struct layouts are extremely stable; keep as fallback.
    "FCameraCacheEntry::POV": 0x10,
    "FMinimalViewInfo::Location": 0x0,
    "FMinimalViewInfo::Rotation": 0x18,
    "FMinimalViewInfo::FOV": 0x30,
}


# ---------------------------------------------------------------------------
# Dynamic offset resolver: walks class FField property chains.
# ---------------------------------------------------------------------------
class OffsetResolver:
    """Resolves engine class property offsets by walking ChildProperties."""

    def __init__(self, pm, objects):
        self.pm = pm
        self.objects = objects
        self.cache = dict(OFFSETS)

    def _field_name(self, field):
        return self.objects.fnames.resolve(ru32(self.pm, field + self.cache["FField::NamePrivate"]))

    def _resolve_on_class(self, cls, prop_name):
        prop = rp(self.pm, cls + self.cache["UStruct::ChildProperties"])
        depth = 0
        while prop and depth < 512:
            name = self._field_name(prop)
            if name == prop_name:
                return ru32(self.pm, prop + self.cache["FProperty::Offset_Internal"])
            prop = rp(self.pm, prop + self.cache["FField::Next"])
            depth += 1
        return None

    def resolve(self, class_name, prop_name):
        key = f"{class_name}::{prop_name}"
        if key in self.cache:
            return self.cache[key]
        cls = self.objects.find_class(class_name)
        if not cls:
            return None
        offset = self._resolve_on_class(cls, prop_name)
        seen = {cls}
        while offset is None:
            super_cls = rp(self.pm, cls + self.cache["UStruct::SuperStruct"])
            if not super_cls or super_cls in seen:
                break
            seen.add(super_cls)
            offset = self._resolve_on_class(super_cls, prop_name)
        if offset is not None:
            self.cache[key] = offset
        return offset

    def resolve_map(self, mapping):
        out = {}
        for key, (cls, prop) in mapping.items():
            val = self.resolve(cls, prop)
            if val is None:
                raise RuntimeError(f"Could not resolve offset {key} ({cls}.{prop})")
            out[key] = val
        return out


# ---------------------------------------------------------------------------
# Memory primitives
# ---------------------------------------------------------------------------
def rp(pm, addr):
    try:
        return struct.unpack("<Q", pm.read_bytes(addr, 8))[0]
    except Exception:
        return 0


def ru32(pm, addr):
    try:
        return struct.unpack("<I", pm.read_bytes(addr, 4))[0]
    except Exception:
        return 0


def ru16(pm, addr):
    try:
        return struct.unpack("<H", pm.read_bytes(addr, 2))[0]
    except Exception:
        return 0


def rfloat(pm, addr):
    try:
        return struct.unpack("<f", pm.read_bytes(addr, 4))[0]
    except Exception:
        return 0.0


def wdouble(pm, addr, value):
    try:
        pm.write_bytes(addr, struct.pack("<d", value), 8)
        return True
    except Exception:
        return False


def rvec3(pm, addr):
    try:
        return struct.unpack("<ddd", pm.read_bytes(addr, 24))
    except Exception:
        return (0.0, 0.0, 0.0)


def rrot(pm, addr):
    """Read an FRotator (Pitch/Yaw/Roll as floats, 12 bytes)."""
    try:
        return struct.unpack("<fff", pm.read_bytes(addr, 12))
    except Exception:
        return (0.0, 0.0, 0.0)


def rfstring(pm, addr, max_len=64):
    """Read an FString (TArray<TCHAR>: Data ptr, Num, Max) as UTF-16."""
    try:
        data = rp(pm, addr)
        num = struct.unpack("<i", pm.read_bytes(addr + 8, 4))[0]
        if not data or num <= 0 or num > max_len:
            return ""
        raw = pm.read_bytes(data, num * 2)
        return raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
    except Exception:
        return ""


def read_array(pm, addr):
    try:
        data = rp(pm, addr)
        count = ru32(pm, addr + 8)
        cap = ru32(pm, addr + 0x10)
        return data, count, cap
    except Exception:
        return 0, 0, 0


def dist(a, b):
    return math.sqrt((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2 + (a[2] - b[2]) ** 2)


# ---------------------------------------------------------------------------
# Pattern scanner
# ---------------------------------------------------------------------------
class PatternScanner:
    CHUNK_SIZE = 0x200000  # 2 MiB chunks to avoid huge allocations on shipping exes

    def __init__(self, pm, module_name):
        self.pm = pm
        self.module = pymem.process.module_from_name(pm.process_handle, module_name)
        if not self.module:
            raise RuntimeError(f"Module {module_name} not found")
        self.base = self.module.lpBaseOfDll
        self.size = self.module.SizeOfImage

    def _match_at(self, data, offset, pattern, mask):
        pat_len = len(pattern)
        for j in range(pat_len):
            if mask[j] and data[offset + j] != pattern[j]:
                return False
        return True

    def scan_all(self, pattern, mask):
        """Yield every match address in ascending order."""
        pat_len = len(pattern)
        if pat_len == 0 or self.size == 0:
            return
        step = self.CHUNK_SIZE
        for start in range(0, self.size, step):
            # Overlap reads by pat_len so patterns spanning chunk boundaries aren't missed.
            end = min(start + step + pat_len, self.size)
            read_size = end - start
            try:
                data = self.pm.read_bytes(self.base + start, read_size)
            except Exception:
                continue
            scan_len = len(data) - pat_len
            for i in range(scan_len):
                if self._match_at(data, i, pattern, mask):
                    yield self.base + start + i

    def scan(self, pattern, mask):
        for addr in self.scan_all(pattern, mask):
            return addr
        return 0


# ---------------------------------------------------------------------------
# FName + object array
# ---------------------------------------------------------------------------
class FNameResolver:
    # FNamePool block-pointer tables sit at different offsets depending on UE5 version.
    BLOCK_TABLE_OFFSETS = (0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38,
                           0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70)

    def __init__(self, pm, fname_pool):
        self.pm = pm
        self.fname_pool = fname_pool
        self.block_table_off = 0x10
        self.header_style = "ue5"  # or "ue4"
        self._detect_layout()

    def _read_entry(self, entry_id, table_off, style):
        block_idx = entry_id >> 16
        within = (entry_id & 0xFFFF) << 1
        block_addr = rp(self.pm, self.fname_pool + table_off + block_idx * 8)
        if not block_addr:
            return None
        hdr = ru16(self.pm, block_addr + within)
        if style == "ue4":
            # UE4: bIsWide (1 bit), Len (15 bits)
            is_wide = hdr & 1
            length = hdr >> 1
        elif style == "custom":
            # MECCHA CHAMELEON build: bIsWide (bit 0), Len (bits 6-15)
            is_wide = hdr & 1
            length = (hdr >> 6) & 0x3FF
        else:
            # Standard UE5: Len (10 bits), bIsWide (1 bit), LowercaseProbeHash (5 bits)
            length = hdr & 0x3FF
            is_wide = (hdr >> 10) & 1
        if length == 0 or length > 512:
            return None
        if is_wide:
            raw = self.pm.read_bytes(block_addr + within + 2, length * 2)
            return raw.decode("utf-16-le", errors="ignore")
        else:
            raw = self.pm.read_bytes(block_addr + within + 2, length)
            return raw.decode("latin-1")

    def _detect_layout(self):
        """Probe block-table offsets and header styles until entry 0 is 'None'."""
        for off in self.BLOCK_TABLE_OFFSETS:
            for style in ("custom", "ue5", "ue4"):
                try:
                    if self._read_entry(0, off, style) == "None":
                        self.block_table_off = off
                        self.header_style = style
                        return
                except Exception:
                    continue

    def resolve(self, entry_id):
        try:
            name = self._read_entry(entry_id, self.block_table_off, self.header_style)
            if name is not None:
                return name
        except Exception:
            pass
        # If the cached layout fails, re-probe once per call until something works.
        for off in self.BLOCK_TABLE_OFFSETS:
            for style in ("custom", "ue5", "ue4"):
                if off == self.block_table_off and style == self.header_style:
                    continue
                try:
                    name = self._read_entry(entry_id, off, style)
                    if name is not None:
                        self.block_table_off = off
                        self.header_style = style
                        return name
                except Exception:
                    continue
        return None


class UObjectArray:
    def __init__(self, pm, guobject_array, fname_pool):
        self.pm = pm
        self.guobject_array = guobject_array
        self.fnames = FNameResolver(pm, fname_pool)
        self._meta_class_addr = None
        self._class_cache = {}

    def _obj_name(self, obj):
        return self.fnames.resolve(ru32(self.pm, obj + OFFSETS["UObjectBase::NamePrivate"]))

    def _obj_class(self, obj):
        return rp(self.pm, obj + OFFSETS["UObjectBase::ClassPrivate"])

    def iter_objects(self):
        objects_ptr = rp(self.pm, self.guobject_array + 0x10)
        if not objects_ptr:
            return
        chunk_idx = 0
        while chunk_idx < 64:
            chunk = rp(self.pm, objects_ptr + chunk_idx * 8)
            if not chunk:
                break
            for within in range(0x10000):
                obj = rp(self.pm, chunk + within * 0x18)
                if obj:
                    yield obj
            chunk_idx += 1

    def _meta_class(self):
        # Don't cache a failed search; the object array may still be loading.
        if self._meta_class_addr is None or not self._meta_class_addr:
            for obj in self.iter_objects():
                if self._obj_name(obj) == "Class":
                    self._meta_class_addr = obj
                    break
        return self._meta_class_addr

    def find_class(self, name):
        cached = self._class_cache.get(name)
        if cached:
            # Validate the cached pointer still names itself correctly.
            if self._obj_name(cached) == name:
                return cached
            del self._class_cache[name]
        meta = self._meta_class()
        if not meta:
            return 0
        for obj in self.iter_objects():
            if self._obj_class(obj) == meta and self._obj_name(obj) == name:
                self._class_cache[name] = obj
                return obj
        return 0

    def find_first_instance(self, class_name, skip_default=True):
        cls = self.find_class(class_name)
        if not cls:
            return 0
        for obj in self.iter_objects():
            if self._obj_class(obj) == cls:
                name = self._obj_name(obj)
                if skip_default and name and name.startswith("Default__"):
                    continue
                return obj
        return 0


# ---------------------------------------------------------------------------
# Game reader
# ---------------------------------------------------------------------------
class MecchaESP:
    PROCESS_NAME = "PenguinHotel-Win64-Shipping.exe"
    MODULE_NAME = "PenguinHotel-Win64-Shipping.exe"

    GUOBJECT_SIG = bytes([
        0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x01, 0x45, 0x8B, 0xD1
    ])
    GUOBJECT_MASK = bytes([1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1])

    # Multiple FNamePool references can appear; we verify by trying to read names.
    FNAMEPOOL_PATTERNS = (
        # lea rcx,[FNamePool]; call FName::FName; mov r8,rax
        (bytes([0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
                0xE8, 0x00, 0x00, 0x00, 0x00,
                0x4C, 0x8B, 0xC0]),
         bytes([1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1])),
        # lea rcx,[FNamePool]; call FName::FName; mov rax,[rbx+...]
        (bytes([0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
                0xE8, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x8B]),
         bytes([1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1])),
        # lea rsi,[FNamePool]
        (bytes([0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00]),
         bytes([1, 1, 1, 0, 0, 0, 0])),
        # lea rdi,[FNamePool]
        (bytes([0x48, 0x8D, 0x3D, 0x00, 0x00, 0x00, 0x00]),
         bytes([1, 1, 1, 0, 0, 0, 0])),
    )
    FNAMEPOOL_DELTA = 0xE3B40

    OFFSET_MAP = {
        "UWorld::GameState": ("World", "GameState"),
        "UWorld::OwningGameInstance": ("World", "OwningGameInstance"),
        "UGameInstance::LocalPlayers": ("GameInstance", "LocalPlayers"),
        "UPlayer::PlayerController": ("Player", "PlayerController"),
        "UEngine::GameViewport": ("Engine", "GameViewport"),
        "UGameViewportClient::World": ("GameViewportClient", "World"),
        "AGameStateBase::PlayerArray": ("GameStateBase", "PlayerArray"),
        "APlayerState::PawnPrivate": ("PlayerState", "PawnPrivate"),
        "APlayerState::PlayerNamePrivate": ("PlayerState", "PlayerNamePrivate"),
        "AController::PlayerState": ("Controller", "PlayerState"),
        "AController::ControlRotation": ("Controller", "ControlRotation"),
        "APawn::PlayerState": ("Pawn", "PlayerState"),
        "APlayerController::AcknowledgedPawn": ("PlayerController", "AcknowledgedPawn"),
        "APlayerController::PlayerCameraManager": ("PlayerController", "PlayerCameraManager"),
        "APlayerCameraManager::CameraCachePrivate": ("PlayerCameraManager", "CameraCachePrivate"),
        "AActor::RootComponent": ("Actor", "RootComponent"),
        "USceneComponent::RelativeLocation": ("SceneComponent", "RelativeLocation"),
        "USceneComponent::RelativeRotation": ("SceneComponent", "RelativeRotation"),
        "USceneComponent::RelativeScale3D": ("SceneComponent", "RelativeScale3D"),
        "USceneComponent::AttachChildren": ("SceneComponent", "AttachChildren"),
        "USkinnedMeshComponent::SkeletalMesh": ("SkinnedMeshComponent", "SkeletalMesh"),
        # Note: UWorld::PersistentLevel and ULevel::Actors are only used in the
        # level-actors fallback; they are resolved lazily with hardcoded defaults.
    }

    # Bone pose/name data are internal runtime caches with no UPROPERTY, so
    # they can't be found via reflection -- these are literal offsets found by
    # empirically scanning this exact game build (MECCHA CHAMELEON 5.6.1) with
    # a self-validating scanner (checked unit-length quaternions, plausible
    # bone counts, and FNames that resolve to real ASCII bone names like
    # "spine1"/"Head"/"hand_L"). Unlike everything else in OFFSET_MAP, these
    # aren't resolvable via reflection, so they can't self-heal the same way.
    #
    # These two constants are just the last-known-good starting guess (from
    # game build 5.6.1), not a hard requirement: _resolve_bone_transforms_offset()
    # / _resolve_bone_info_offset() validate them live on first use (unit-length
    # quaternions / FNames that resolve to real bone-name strings) and, if a
    # game update has shifted the layout, automatically re-scan the object body
    # to find the new offset and keep using that for the rest of the session --
    # no manual re-scan needed unless auto-discovery itself can't find a
    # confident match.
    BONE_TRANSFORMS_OFFSET = 0x5F0   # USkinnedMeshComponent -> TArray<FTransform>
    BONE_INFO_OFFSET = 0x340         # USkeletalMesh -> TArray<FMeshBoneInfo>
    BONE_INFO_ENTRY_SIZE = 12        # FName (8B) + ParentIndex (int32)
    FTRANSFORM_SIZE = 0x60
    STRUCT_SIZE_OFF = 0x58           # Off::UStruct::Size, from the Dumper-7 SDK for this build

    def __init__(self):
        self.pm = self._wait_for_process()
        print("Waiting on injection...")
        self.guobject_array = self._scan_guobject_array()
        if not self.guobject_array:
            raise RuntimeError("Could not find GUObjectArray via pattern scan")
        self.fname_pool = self._scan_fname_pool()
        if not self.fname_pool:
            raise RuntimeError("Could not find FNamePool via pattern scan or delta fallback")
        self.objects = UObjectArray(self.pm, self.guobject_array, self.fname_pool)
        # Sanity-check globals; on failure we still open, but warn in overlay.
        self._globals_ok = self._verify_globals()
        self.resolver = OffsetResolver(self.pm, self.objects)
        self.offsets = self.resolver.resolve_map(self.OFFSET_MAP)
        # Fill in the stable nested struct offsets from the bootstrap dict.
        for key in ("FCameraCacheEntry::POV", "FMinimalViewInfo::Location",
                    "FMinimalViewInfo::Rotation", "FMinimalViewInfo::FOV"):
            self.offsets[key] = OFFSETS[key]
        self.gengine = self.objects.find_first_instance("GameEngine")
        if not self.gengine:
            raise RuntimeError("Could not find GEngine instance")
        self._bone_hierarchy_cache = {}  # mesh asset addr -> [(name, parent_index), ...]
        self._bone_transforms_offset = None  # resolved lazily; see _resolve_bone_transforms_offset
        self._bone_info_offset = None        # resolved lazily; see _resolve_bone_info_offset
        print("Injected")

    def _wait_for_process(self):
        printed = False
        while True:
            try:
                return pymem.Pymem(self.PROCESS_NAME)
            except pymem.exception.ProcessNotFound:
                if not printed:
                    print("Waiting on game...")
                    printed = True
                time.sleep(1)

    def _scan_guobject_array(self):
        scanner = PatternScanner(self.pm, self.MODULE_NAME)
        addr = scanner.scan(self.GUOBJECT_SIG, self.GUOBJECT_MASK)
        if not addr:
            return 0
        rel = struct.unpack("<i", self.pm.read_bytes(addr + 3, 4))[0]
        return addr + 7 + rel

    def _scan_fname_pool(self):
        # The delta has been stable for this build; use it as the default.
        delta_candidate = self.guobject_array - self.FNAMEPOOL_DELTA
        if self._verify_fname_pool(delta_candidate):
            return delta_candidate
        # Try a few common FNamePool signatures as backups.
        scanner = PatternScanner(self.pm, self.MODULE_NAME)
        for sig, mask in self.FNAMEPOOL_PATTERNS:
            for addr in scanner.scan_all(sig, mask):
                rel = struct.unpack("<i", self.pm.read_bytes(addr + 3, 4))[0]
                candidate = addr + 7 + rel
                if self._verify_fname_pool(candidate):
                    return candidate
        # Even if unverified, fall back to the delta so the ESP can still open.
        # Name resolution may self-correct via the resolver's lazy offset probe.
        return delta_candidate

    def _verify_fname_pool(self, pool_addr):
        resolver = FNameResolver(self.pm, pool_addr)
        if resolver.resolve(0) == "None":
            return True
        # Some builds don't keep "None" at id 0; settle for any printable name.
        for probe in (0, 1, 2, 3, 4, 5):
            name = resolver.resolve(probe)
            if name and 0 < len(name) <= 128 and name.isprintable():
                return True
        return False

    def _verify_globals(self):
        # GUObjectArray + 0x10 is TUObjectArray::Objects; read its header.
        obj_array = self.guobject_array + 0x10
        num = ru32(self.pm, obj_array + 0x14)
        max_chunks = ru32(self.pm, obj_array + 0x18)
        if num == 0 or num > 10_000_000 or max_chunks == 0 or max_chunks > 64:
            return False
        # We should be able to find the meta Class object.
        return self.objects.find_class("Class") != 0

    def _get_world(self):
        viewport = rp(self.pm, self.gengine + self.offsets["UEngine::GameViewport"])
        if not viewport:
            return 0
        return rp(self.pm, viewport + self.offsets["UGameViewportClient::World"])

    def _get_local_controller(self, world):
        if not world:
            return 0
        gi = rp(self.pm, world + self.offsets["UWorld::OwningGameInstance"])
        if not gi:
            return 0
        lp_data, lp_count, _ = read_array(self.pm, gi + self.offsets["UGameInstance::LocalPlayers"])
        if not lp_data or lp_count == 0:
            return 0
        local_player = rp(self.pm, lp_data)
        if not local_player:
            return 0
        return rp(self.pm, local_player + self.offsets["UPlayer::PlayerController"])

    def _read_pov(self, pov_addr):
        """Read a minimal view POV from the given address."""
        return {
            "loc": rvec3(self.pm, pov_addr + self.offsets["FMinimalViewInfo::Location"]),
            "rot": rvec3(self.pm, pov_addr + self.offsets["FMinimalViewInfo::Rotation"]),
            "fov": rfloat(self.pm, pov_addr + self.offsets["FMinimalViewInfo::FOV"]),
        }

    def get_camera(self):
        world = self._get_world()
        if not world:
            return None
        pc = self._get_local_controller(world)
        if not pc:
            return None
        cam = rp(self.pm, pc + self.offsets["APlayerController::PlayerCameraManager"])
        if not cam:
            return None

        # Primary: CameraCachePrivate (always reflects the current camera).
        cc = cam + self.offsets["APlayerCameraManager::CameraCachePrivate"]
        pov = cc + self.offsets["FCameraCacheEntry::POV"]
        try:
            camera = self._read_pov(pov)
        except Exception:
            camera = None

        # Fallback: PlayerCameraManager->ViewTarget.POV (some spectate/free-look modes).
        if (camera is None or
            (abs(camera["loc"][0]) < 0.01 and abs(camera["loc"][1]) < 0.01 and abs(camera["loc"][2]) < 0.01) or
            camera["fov"] <= 0.0):
            vt_off = self.offsets.get("APlayerCameraManager::ViewTarget")
            vt_pov_off = self.offsets.get("FTViewTarget::POV")
            if vt_off is not None and vt_pov_off is not None:
                try:
                    fallback = self._read_pov(cam + vt_off + vt_pov_off)
                    if fallback["fov"] > 0.0:
                        camera = fallback
                except Exception:
                    pass

        if camera is None or camera["fov"] <= 0.0:
            return None
        return camera

    def _class_name(self, obj):
        if not obj:
            return ""
        cls = rp(self.pm, obj + OFFSETS["UObjectBase::ClassPrivate"])
        return self.objects._obj_name(cls) if cls else ""

    def _player_name(self, playerstate):
        if not playerstate:
            return ""
        off = self.offsets.get("APlayerState::PlayerNamePrivate")
        if off is None:
            return ""
        return rfstring(self.pm, playerstate + off)

    def _pawn_controller(self, pawn):
        if not pawn:
            return 0
        off = self.offsets.get("APawn::Controller")
        if off is None:
            return 0
        return rp(self.pm, pawn + off)

    def _pawn_playerstate(self, pawn):
        if not pawn:
            return 0
        off = self.offsets.get("APawn::PlayerState")
        if off is None:
            return 0
        return rp(self.pm, pawn + off)

    def _actor_owner(self, actor):
        if not actor:
            return 0
        off = self.offsets.get("AActor::Owner")
        if off is None:
            return 0
        return rp(self.pm, actor + off)

    def _component_world_pos(self, component):
        """Read a USceneComponent's world translation from ComponentToWorld."""
        if not component:
            return None
        ctw_off = self.offsets.get("USceneComponent::ComponentToWorld")
        trans_off = self.offsets.get("FTransform::Translation")
        if ctw_off is None or trans_off is None:
            return None
        try:
            return rvec3(self.pm, component + ctw_off + trans_off)
        except Exception:
            return None

    def _actor_position(self, actor):
        """Return the best available world position for an actor.

        The old RelativeLocation path was working for this game, so it stays
        primary. ComponentToWorld is only used as a fallback if RelativeLocation
        is missing or clearly uninitialized.
        """
        if not actor:
            return None
        root = rp(self.pm, actor + self.offsets["AActor::RootComponent"])
        if root:
            rel_off = self.offsets.get("USceneComponent::RelativeLocation")
            if rel_off is not None:
                try:
                    pos = rvec3(self.pm, root + rel_off)
                    # Only fall through to ComponentToWorld if RelativeLocation
                    # is clearly uninitialized (origin-only).
                    if not (abs(pos[0]) < 0.01 and abs(pos[1]) < 0.01 and abs(pos[2]) < 0.01):
                        return pos
                except Exception:
                    pass
            # Fallback: world-space transform.
            pos = self._component_world_pos(root)
            if pos is not None:
                return pos
        # Last resort: mesh world transform.
        mesh_off = self.offsets.get("ACharacter::Mesh")
        if mesh_off is not None:
            mesh = rp(self.pm, actor + mesh_off)
            if mesh:
                pos = self._component_world_pos(mesh)
                if pos is not None:
                    return pos
        return None

    def _scene_component_transform(self, component):
        """A component's own (Location, Quat, Scale) in ITS PARENT's space --
        not world space. For a component with no attach parent (e.g. an
        actor's RootComponent), this already IS the world transform."""
        loc = rvec3(self.pm, component + self.offsets["USceneComponent::RelativeLocation"])
        rot = rvec3(self.pm, component + self.offsets["USceneComponent::RelativeRotation"])
        scale = rvec3(self.pm, component + self.offsets["USceneComponent::RelativeScale3D"])
        return loc, rotator_to_quat(rot), scale

    def _find_skeletal_mesh_component(self, actor):
        """Walk RootComponent's attached children for a SkeletalMeshComponent.

        This pawn's actual class chain is Pawn -> MoverExamplesCharacter ->
        ... (a custom Mover-plugin character, not stock ACharacter), so there
        is no inherited "Mesh" property to resolve via reflection. Every
        character does still attach a skeletal mesh as a child of its
        capsule, so walking the real attachment tree works regardless.
        """
        if not actor:
            return 0
        root = rp(self.pm, actor + self.offsets["AActor::RootComponent"])
        if not root:
            return 0
        attach_off = self.offsets.get("USceneComponent::AttachChildren")
        if attach_off is None:
            return 0
        data, count, _ = read_array(self.pm, root + attach_off)
        if not data or count <= 0 or count > 64:
            return 0
        for i in range(count):
            child = rp(self.pm, data + i * 8)
            if child and self._class_name(child) == "SkeletalMeshComponent":
                return child
        return 0

    def _object_size(self, obj_addr):
        cls = rp(self.pm, obj_addr + OFFSETS["UObjectBase::ClassPrivate"])
        if not cls:
            return 0
        return ru32(self.pm, cls + self.STRUCT_SIZE_OFF)

    def _validate_transform_header(self, base_addr, offset):
        """Does base_addr+offset look like a real TArray<FTransform> (bone
        pose cache)? Checked via unit-length quaternions, not just a
        plausible-looking pointer/count (those alone produce false positives)."""
        data, count, _ = read_array(self.pm, base_addr + offset)
        if not data or not (3 <= count <= 300):
            return False
        n = min(count, 20)
        try:
            raw = self.pm.read_bytes(data, n * self.FTRANSFORM_SIZE)
        except Exception:
            return False
        hits = 0
        for i in range(n):
            chunk = raw[i * self.FTRANSFORM_SIZE:(i + 1) * self.FTRANSFORM_SIZE]
            if len(chunk) < 32:
                break
            qx, qy, qz, qw = struct.unpack_from("<dddd", chunk, 0)
            if 0.8 <= (qx * qx + qy * qy + qz * qz + qw * qw) <= 1.2:
                hits += 1
        return hits >= n * 0.85

    def _discover_bone_transforms_offset(self, mesh_component):
        size = self._object_size(mesh_component)
        if not size:
            return None
        for rel in range(0, max(size - 0x18, 0), 4):
            if self._validate_transform_header(mesh_component, rel):
                return rel
        return None

    def _resolve_bone_transforms_offset(self, mesh_component):
        """Bone-transform-array offset within USkinnedMeshComponent, validated
        (or auto-rediscovered) against the live game rather than trusted
        blindly -- see the comment on BONE_TRANSFORMS_OFFSET."""
        if self._bone_transforms_offset is not None:
            return self._bone_transforms_offset
        if self._validate_transform_header(mesh_component, self.BONE_TRANSFORMS_OFFSET):
            self._bone_transforms_offset = self.BONE_TRANSFORMS_OFFSET
            return self._bone_transforms_offset
        found = self._discover_bone_transforms_offset(mesh_component)
        if found is not None:
            print(f"[MCESP] Bone transform offset auto-detected at {hex(found)} "
                  f"(hardcoded default {hex(self.BONE_TRANSFORMS_OFFSET)} didn't "
                  f"validate -- game update?)")
            self._bone_transforms_offset = found
        return found

    def _validate_bone_info_header(self, base_addr, offset, entry_size):
        """Does base_addr+offset look like a real TArray<FMeshBoneInfo> (bone
        name/hierarchy table)? Checked via FNames that resolve to real ASCII
        strings, not just a plausible-looking pointer/count."""
        data, count, _ = read_array(self.pm, base_addr + offset)
        if not data or not (3 <= count <= 300):
            return False
        try:
            raw = self.pm.read_bytes(data, count * entry_size)
        except Exception:
            return False
        good = 0
        for i in range(count):
            chunk = raw[i * entry_size:(i + 1) * entry_size]
            if len(chunk) < 4:
                break
            fname_index = struct.unpack_from("<I", chunk, 0)[0]
            try:
                name = self.objects.fnames.resolve(fname_index)
            except Exception:
                name = None
            if name and name.isascii() and name.isprintable() and 1 <= len(name) <= 40:
                good += 1
        return good >= count * 0.85

    def _discover_bone_info_offset(self, mesh_asset):
        size = self._object_size(mesh_asset)
        if not size:
            return None
        for rel in range(0, max(size - 0x18, 0), 4):
            for entry_size in (12, 8, 16):
                if self._validate_bone_info_header(mesh_asset, rel, entry_size):
                    return rel, entry_size
        return None

    def _resolve_bone_info_offset(self, mesh_asset):
        """(offset, entry_size) for the bone name/hierarchy table within
        USkeletalMesh, validated (or auto-rediscovered) against the live
        game -- see the comment on BONE_INFO_OFFSET."""
        if self._bone_info_offset is not None:
            return self._bone_info_offset
        if self._validate_bone_info_header(mesh_asset, self.BONE_INFO_OFFSET, self.BONE_INFO_ENTRY_SIZE):
            self._bone_info_offset = (self.BONE_INFO_OFFSET, self.BONE_INFO_ENTRY_SIZE)
            return self._bone_info_offset
        found = self._discover_bone_info_offset(mesh_asset)
        if found is not None:
            print(f"[MCESP] Bone name offset auto-detected at {hex(found[0])} "
                  f"entry_size={found[1]} (hardcoded default {hex(self.BONE_INFO_OFFSET)} "
                  f"didn't validate -- game update?)")
            self._bone_info_offset = found
        return found

    def _read_bone_hierarchy(self, mesh_asset):
        """[(bone_name, parent_index), ...] for a USkeletalMesh, cached by
        asset pointer since it's static reference data, not per-frame pose."""
        cached = self._bone_hierarchy_cache.get(mesh_asset)
        if cached is not None:
            return cached
        resolved = self._resolve_bone_info_offset(mesh_asset)
        if resolved is None:
            return []
        offset, entry_size = resolved
        data, count, _ = read_array(self.pm, mesh_asset + offset)
        if not data or count <= 0 or count > 300:
            self._bone_info_offset = None  # stopped validating -- retry next call
            return []
        try:
            raw = self.pm.read_bytes(data, count * entry_size)
        except Exception:
            return []
        bones = []
        for i in range(count):
            chunk = raw[i * entry_size:(i + 1) * entry_size]
            fname_index = struct.unpack_from("<I", chunk, 0)[0]
            parent_index = struct.unpack_from("<i", chunk, 8)[0]
            name = self.objects.fnames.resolve(fname_index) or f"bone_{i}"
            bones.append((name, parent_index))
        self._bone_hierarchy_cache[mesh_asset] = bones
        return bones

    def _read_bone_transforms(self, mesh_component):
        """[(loc, quat, scale), ...] per bone, in the mesh component's own
        (component) space -- one live pose read per call, not cached."""
        offset = self._resolve_bone_transforms_offset(mesh_component)
        if offset is None:
            return []
        data, count, _ = read_array(self.pm, mesh_component + offset)
        if not data or count <= 0 or count > 300:
            self._bone_transforms_offset = None  # stopped validating -- retry next call
            return []
        size = self.FTRANSFORM_SIZE
        try:
            raw = self.pm.read_bytes(data, count * size)
        except Exception:
            return []
        transforms = []
        for i in range(count):
            chunk = raw[i * size:(i + 1) * size]
            qx, qy, qz, qw = struct.unpack_from("<dddd", chunk, 0)
            tx, ty, tz, _ = struct.unpack_from("<dddd", chunk, 32)
            sx, sy, sz, _ = struct.unpack_from("<dddd", chunk, 64)
            transforms.append(((tx, ty, tz), (qx, qy, qz, qw), (sx, sy, sz)))
        return transforms

    def get_skeleton_world_positions(self, actor):
        """{bone_name: (world_pos, parent_bone_name_or_None)} for an actor's
        skeletal mesh, or {} if any part of the chain isn't available."""
        mesh_component = self._find_skeletal_mesh_component(actor)
        if not mesh_component:
            return {}
        skel_mesh_off = self.offsets.get("USkinnedMeshComponent::SkeletalMesh")
        mesh_asset = rp(self.pm, mesh_component + skel_mesh_off) if skel_mesh_off is not None else 0
        if not mesh_asset:
            return {}
        hierarchy = self._read_bone_hierarchy(mesh_asset)
        transforms = self._read_bone_transforms(mesh_component)
        if not hierarchy or not transforms or len(hierarchy) != len(transforms):
            return {}

        root = rp(self.pm, actor + self.offsets["AActor::RootComponent"])
        if not root:
            return {}
        # RootComponent has no attach parent, so its own Relative transform
        # already IS its world transform; compose the mesh's transform
        # (relative to root) on top of that to get the mesh's world transform.
        root_world = self._scene_component_transform(root)
        mesh_world = compose_transform(root_world, self._scene_component_transform(mesh_component))

        result = {}
        for i, (name, parent_index) in enumerate(hierarchy):
            bone_world = compose_transform(mesh_world, transforms[i])
            parent_name = hierarchy[parent_index][0] if 0 <= parent_index < len(hierarchy) else None
            result[name] = (bone_world[0], parent_name)
        return result

    def iter_players(self, include_local=False, players_only=False):
        world = self._get_world()
        if not world:
            self._last_iter_stats = {"pa_total": 0, "pa_valid": 0,
                                     "level_total": 0, "level_valid": 0,
                                     "rendered": 0}
            return
        gamestate = rp(self.pm, world + self.offsets["UWorld::GameState"])
        pc = self._get_local_controller(world)
        local_pawn = rp(self.pm, pc + self.offsets["APlayerController::AcknowledgedPawn"]) if pc else 0
        local_ps = rp(self.pm, pc + self.offsets["AController::PlayerState"]) if pc else 0

        stats = {"pa_total": 0, "pa_valid": 0,
                 "level_total": 0, "level_valid": 0,
                 "rendered": 0}
        seen = set()

        def _is_valid_target(pawn):
            if not pawn:
                return False
            cls_name = self._class_name(pawn)
            if not cls_name:
                return False
            # Default logic: show every live Character in the world. Team filters
            # are intentionally gone because they hide players in free-look/spectate
            # and across game modes where pawn classes overlap.
            return "Character" in cls_name and "Spectate" not in cls_name

        def _emit_actor(actor, idx, stat_key, name=""):
            pos = self._actor_position(actor)
            if pos is None:
                return
            # Drop uninitialized / origin-only positions.
            if abs(pos[0]) < 0.01 and abs(pos[1]) < 0.01 and abs(pos[2]) < 0.01:
                return
            stats[stat_key] += 1
            stats["rendered"] += 1
            yield False, pos, idx, name or f"Enemy {idx}", actor

        # Local marker for calibration.
        if include_local and local_pawn:
            pos = self._actor_position(local_pawn)
            if pos is not None:
                stats["rendered"] += 1
                yield True, pos, 0, self._player_name(local_ps) or "YOU", local_pawn

        # Pass 1: GameState->PlayerArray.
        yielded = 0
        if gamestate:
            pa_data, pa_count, _ = read_array(self.pm, gamestate + self.offsets["AGameStateBase::PlayerArray"])
            stats["pa_total"] = pa_count
            if pa_data and pa_count > 0:
                for i in range(pa_count):
                    ps = rp(self.pm, pa_data + i * 8)
                    if not ps or ps == local_ps:
                        continue
                    pawn = rp(self.pm, ps + self.offsets["APlayerState::PawnPrivate"])
                    if not pawn or pawn == local_pawn or pawn in seen:
                        continue
                    pawn_cls = self._class_name(pawn)
                    if not pawn_cls:
                        continue
                    seen.add(pawn)
                    if not _is_valid_target(pawn):
                        continue
                    yield from _emit_actor(pawn, i, "pa_valid", self._player_name(ps))
                    yielded += 1

        # Pass 2: Persistent level actors (fallback / merge).
        # Catches players PlayerArray hasn't updated yet. The aimbot intentionally
        # skips this pass to avoid locking onto random NPCs or dummy pawns.
        persistent_level_off = self.offsets.get("UWorld::PersistentLevel", 0x30)
        level = rp(self.pm, world + persistent_level_off) if not players_only else 0
        if level:
            actors_off = self.offsets.get("ULevel::Actors", 0xA0)
            actors_data, actors_count, _ = read_array(self.pm, level + actors_off)
            stats["level_total"] = actors_count
            if actors_data and actors_count > 0 and actors_count < 10000:
                for i in range(actors_count):
                    actor = rp(self.pm, actors_data + i * 8)
                    if not actor or actor == local_pawn or actor in seen:
                        continue
                    cls_name = self._class_name(actor)
                    if not cls_name or "Character" not in cls_name:
                        continue
                    seen.add(actor)
                    if not _is_valid_target(actor):
                        continue
                    name = self._player_name(self._pawn_playerstate(actor))
                    yield from _emit_actor(actor, i, "level_valid", name)

        self._last_iter_stats = stats


# ---------------------------------------------------------------------------
# World-to-screen
# ---------------------------------------------------------------------------
def rotation_to_axes(rot):
    pitch, yaw, roll = [math.radians(x) for x in rot]
    sp, cp = math.sin(pitch), math.cos(pitch)
    sy, cy = math.sin(yaw), math.cos(yaw)
    sr, cr = math.sin(roll), math.cos(roll)

    forward = (cp * cy, cp * sy, sp)
    right = (sr * sp * cy - cr * sy, sr * sp * sy + cr * cy, -sr * cp)
    up = (-(cr * sp * cy + sr * sy), cy * sr - cr * sp * sy, cr * cp)
    return forward, right, up


def w2s(world_pos, camera, screen_w, screen_h):
    cam_loc = camera["loc"]
    cam_rot = camera["rot"]
    fov = camera["fov"]

    forward, right, up = rotation_to_axes(cam_rot)

    dx = world_pos[0] - cam_loc[0]
    dy = world_pos[1] - cam_loc[1]
    dz = world_pos[2] - cam_loc[2]

    view_x = dx * forward[0] + dy * forward[1] + dz * forward[2]
    view_y = dx * right[0] + dy * right[1] + dz * right[2]
    view_z = dx * up[0] + dy * up[1] + dz * up[2]

    if view_x <= 0.1:
        return None

    aspect = screen_w / screen_h
    tan_hfov = math.tan(math.radians(fov) / 2.0)

    ndc_x = view_y / (view_x * tan_hfov)
    ndc_y = view_z / (view_x * tan_hfov / aspect)

    screen_x = (1.0 + ndc_x) * screen_w / 2.0
    screen_y = (1.0 - ndc_y) * screen_h / 2.0

    if not (0 <= screen_x <= screen_w and 0 <= screen_y <= screen_h):
        return None
    return (screen_x, screen_y)


# ---------------------------------------------------------------------------
# Quaternion / transform composition, for turning component-space bone
# transforms (see MecchaESP.get_skeleton_world_positions) into world space.
# ---------------------------------------------------------------------------
def quat_rotate_vector(q, v):
    qx, qy, qz, qw = q
    vx, vy, vz = v
    # v' = v + 2*qw*(q_xyz x v) + 2*(q_xyz x (q_xyz x v))
    tx = 2.0 * (qy * vz - qz * vy)
    ty = 2.0 * (qz * vx - qx * vz)
    tz = 2.0 * (qx * vy - qy * vx)
    return (
        vx + qw * tx + (qy * tz - qz * ty),
        vy + qw * ty + (qz * tx - qx * tz),
        vz + qw * tz + (qx * ty - qy * tx),
    )


def quat_multiply(a, b):
    """a * b -- applies b first, then a (matches FTransform's parent*child convention)."""
    ax, ay, az, aw = a
    bx, by, bz, bw = b
    return (
        aw * bx + ax * bw + ay * bz - az * by,
        aw * by - ax * bz + ay * bw + az * bx,
        aw * bz + ax * by - ay * bx + az * bw,
        aw * bw - ax * bx - ay * by - az * bz,
    )


def compose_transform(parent, child):
    """Combine a parent (loc, quat, scale) with a child transform expressed in
    the parent's local space, returning the child's transform in the parent's
    outer space. Mirrors FTransform's own composition (rotate + scale the
    child's translation into the parent's frame, then multiply rotations)."""
    p_loc, p_quat, p_scale = parent
    c_loc, c_quat, c_scale = child
    scaled_child_loc = (c_loc[0] * p_scale[0], c_loc[1] * p_scale[1], c_loc[2] * p_scale[2])
    rotated = quat_rotate_vector(p_quat, scaled_child_loc)
    world_loc = (p_loc[0] + rotated[0], p_loc[1] + rotated[1], p_loc[2] + rotated[2])
    world_quat = quat_multiply(p_quat, c_quat)
    world_scale = (p_scale[0] * c_scale[0], p_scale[1] * c_scale[1], p_scale[2] * c_scale[2])
    return world_loc, world_quat, world_scale


def rotator_to_quat(rot):
    """FRotator (Pitch, Yaw, Roll) -> FQuat (x, y, z, w).

    Derived from rotation_to_axes() (already proven correct by the working
    camera/ESP projection) via the standard matrix-to-quaternion algorithm,
    rather than trusting a recalled Euler-angle formula. Verified to
    round-trip exactly through quat_rotate_vector() for arbitrary rotations.
    """
    forward, right, up = rotation_to_axes(rot)
    m00, m10, m20 = forward
    m01, m11, m21 = right
    m02, m12, m22 = up
    trace = m00 + m11 + m22
    if trace > 0:
        s = math.sqrt(trace + 1.0) * 2
        qw = 0.25 * s
        qx = (m21 - m12) / s
        qy = (m02 - m20) / s
        qz = (m10 - m01) / s
    elif m00 > m11 and m00 > m22:
        s = math.sqrt(1.0 + m00 - m11 - m22) * 2
        qw = (m21 - m12) / s
        qx = 0.25 * s
        qy = (m01 + m10) / s
        qz = (m02 + m20) / s
    elif m11 > m22:
        s = math.sqrt(1.0 + m11 - m00 - m22) * 2
        qw = (m02 - m20) / s
        qx = (m01 + m10) / s
        qy = 0.25 * s
        qz = (m12 + m21) / s
    else:
        s = math.sqrt(1.0 + m22 - m00 - m11) * 2
        qw = (m10 - m01) / s
        qx = (m02 + m20) / s
        qy = (m12 + m21) / s
        qz = 0.25 * s
    return (qx, qy, qz, qw)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
@dataclass
class Config:
    enabled: bool = True
    box_esp: bool = True
    marker_style: str = "box"  # "dot", "box", or "skeleton"
    show_local: bool = True
    show_names: bool = True
    show_distance: bool = True
    snap_lines: bool = True
    enemy_color: Tuple[int, int, int] = (255, 0, 0)
    local_color: Tuple[int, int, int] = (0, 255, 0)
    box_height_world: float = 100.0
    box_y_offset: int = 0
    dot_radius: int = 8
    show_debug: bool = False
    toggle_key: str = "F2"

    # Aimbot
    aimbot_enabled: bool = False
    aimbot_key: str = "MB5"  # empty string = keyless (always-on while Aimbot Enabled)
    aimbot_fov: int = 150
    aimbot_strength: float = 0.30  # 0.01 = very smooth/slow, 1.0 = instant snap
    aimbot_target_offset: float = 0.0  # 0 = lock on ESP dot; raise for head/chest
    aimbot_show_fov: bool = True


CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "esp_config.json")

# Fields stored as tuples that need to round-trip through JSON lists.
_CONFIG_TUPLE_FIELDS = ("enemy_color", "local_color")


def save_config(config, path=CONFIG_PATH):
    try:
        with open(path, "w") as f:
            json.dump(asdict(config), f, indent=2)
        return True
    except OSError:
        return False


def load_config(config, path=CONFIG_PATH):
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False
    for field in fields(config):
        if field.name not in data:
            continue
        value = data[field.name]
        if field.name in _CONFIG_TUPLE_FIELDS:
            value = tuple(value)
        setattr(config, field.name, value)
    return True


# ---------------------------------------------------------------------------
# Keybind name <-> virtual-key lookup, shared by the menu's key recorder and
# the global hotkey poller in main().
# ---------------------------------------------------------------------------
KEY_NAMES = {
    0x01: "LMB", 0x02: "RMB", 0x04: "MMB", 0x05: "MB4", 0x06: "MB5",
    0x08: "Backspace", 0x09: "Tab", 0x0D: "Enter", 0x10: "Shift",
    0x11: "Ctrl", 0x12: "Alt", 0x13: "Pause", 0x1B: "Esc", 0x20: "Space",
    0x21: "PageUp", 0x22: "PageDown", 0x23: "End", 0x24: "Home",
    0x25: "Left", 0x26: "Up", 0x27: "Right", 0x28: "Down",
    0x2D: "Insert", 0x2E: "Delete",
    0x30: "0", 0x31: "1", 0x32: "2", 0x33: "3", 0x34: "4",
    0x35: "5", 0x36: "6", 0x37: "7", 0x38: "8", 0x39: "9",
    0x41: "A", 0x42: "B", 0x43: "C", 0x44: "D", 0x45: "E", 0x46: "F",
    0x47: "G", 0x48: "H", 0x49: "I", 0x4A: "J", 0x4B: "K", 0x4C: "L",
    0x4D: "M", 0x4E: "N", 0x4F: "O", 0x50: "P", 0x51: "Q", 0x52: "R",
    0x53: "S", 0x54: "T", 0x55: "U", 0x56: "V", 0x57: "W", 0x58: "X",
    0x59: "Y", 0x5A: "Z",
    0x60: "Num0", 0x61: "Num1", 0x62: "Num2", 0x63: "Num3", 0x64: "Num4",
    0x65: "Num5", 0x66: "Num6", 0x67: "Num7", 0x68: "Num8", 0x69: "Num9",
    0x70: "F1", 0x71: "F2", 0x72: "F3", 0x73: "F4", 0x74: "F5",
    0x75: "F6", 0x76: "F7", 0x77: "F8", 0x78: "F9", 0x79: "F10",
    0x7A: "F11", 0x7B: "F12",
    0xBA: ";", 0xBB: "=", 0xBC: ",", 0xBD: "-", 0xBE: ".", 0xBF: "/",
    0xC0: "`", 0xDB: "[", 0xDC: "\\", 0xDD: "]", 0xDE: "'",
}
KEY_VK = {name: vk for vk, name in KEY_NAMES.items()}


# ---------------------------------------------------------------------------
# Menu window
# ---------------------------------------------------------------------------
class Menu(QWidget):
    def __init__(self, config: Config):
        super().__init__()
        self.config = config
        self.setWindowTitle("MECCHA ESP Menu")
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self._drag_pos = None
        self._bound_checks = []   # [(checkbox, attr), ...] for Save/Load refresh
        self._bound_sliders = []  # [(slider, attr, scale, apply_fn), ...]
        self._bound_combos = []   # [(combo, attr, options), ...]

        self._build_ui()

    def _build_ui(self):
        container = QFrame(self)
        container.setStyleSheet("""
            QFrame {
                background-color: rgba(20, 20, 20, 220);
                border: 1px solid #444;
                border-radius: 8px;
            }
            QLabel {
                color: #eee;
                font-size: 12px;
            }
            QCheckBox {
                color: #eee;
                font-size: 12px;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
            QComboBox {
                background-color: #333;
                color: #eee;
                border: 1px solid #555;
                padding: 4px;
            }
            QComboBox QAbstractItemView {
                background-color: #333;
                color: #eee;
                selection-background-color: #0f0;
                selection-color: #111;
                border: 1px solid #555;
                outline: 0;
            }
            QPushButton {
                background-color: #333;
                color: #eee;
                border: 1px solid #555;
                padding: 6px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #444;
            }
            QSlider::groove:horizontal {
                height: 4px;
                background: #3a3a3a;
                border-radius: 2px;
            }
            QSlider::sub-page:horizontal {
                background: #0f0;
                border-radius: 2px;
            }
            QSlider::add-page:horizontal {
                background: #3a3a3a;
                border-radius: 2px;
            }
            QSlider::handle:horizontal {
                background: #eee;
                border: 2px solid #0f0;
                width: 12px;
                height: 12px;
                margin: -5px 0;
                border-radius: 7px;
            }
            QSlider::handle:horizontal:hover {
                background: #0f0;
                border: 2px solid #eee;
            }
            QSlider::handle:horizontal:pressed {
                background: #9f9;
            }
        """)

        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        title = QLabel("MECCHA ESP")
        title.setStyleSheet("font-size: 16px; font-weight: bold; color: #0f0;")
        layout.addWidget(title)

        self.cb_enabled = self._chk("ESP Enabled", "enabled")
        self.cb_box = self._chk("Player Marker", "box_esp")
        self.cb_local = self._chk("Show Local Player", "show_local")
        self.cb_names = self._chk("Show Names", "show_names")
        self.cb_dist = self._chk("Show Distance", "show_distance")
        self.cb_snap = self._chk("Snap Lines", "snap_lines")
        self.cb_debug = self._chk("Show Debug Counters", "show_debug")
        layout.addWidget(self.cb_enabled)
        layout.addWidget(self.cb_box)
        layout.addLayout(self._combo_row("Marker Style:", "marker_style",
            [("Dot", "dot"), ("Box Outline", "box"), ("Skeleton", "skeleton")]))
        layout.addWidget(self.cb_local)
        layout.addWidget(self.cb_names)
        layout.addWidget(self.cb_dist)
        layout.addWidget(self.cb_snap)
        layout.addWidget(self.cb_debug)

        toggle_key_row = QHBoxLayout()
        self.lbl_toggle_key = QLabel(f"ESP Toggle Key: {self.config.toggle_key}")
        self.btn_record_toggle_key = QPushButton("Record Key")
        self.btn_record_toggle_key.clicked.connect(
            lambda: self._start_record_key("toggle_key", self.lbl_toggle_key,
                                            "ESP Toggle Key", self.btn_record_toggle_key))
        toggle_key_row.addWidget(self.lbl_toggle_key)
        toggle_key_row.addWidget(self.btn_record_toggle_key)
        layout.addLayout(toggle_key_row)

        layout.addLayout(self._slider_row("Dot Radius:", "dot_radius", 2, 32))

        color_row = QHBoxLayout()
        self.btn_enemy_color = QPushButton("Enemy Color")
        self.btn_enemy_color.clicked.connect(self._pick_enemy_color)
        self.btn_local_color = QPushButton("Local Color")
        self.btn_local_color.clicked.connect(self._pick_local_color)
        color_row.addWidget(self.btn_enemy_color)
        color_row.addWidget(self.btn_local_color)
        layout.addLayout(color_row)

        layout.addLayout(self._slider_row("Model Height:", "box_height_world", 50, 250, as_float=True))
        layout.addLayout(self._slider_row("Y Offset:", "box_y_offset", -50, 50))

        aim_title = QLabel("AIMBOT")
        aim_title.setStyleSheet("font-size: 14px; font-weight: bold; color: #f0f;")
        layout.addWidget(aim_title)

        self.cb_aimbot = self._chk("Aimbot Enabled", "aimbot_enabled")
        self.cb_aim_fov = self._chk("Show FOV Circle", "aimbot_show_fov")
        layout.addWidget(self.cb_aimbot)
        layout.addWidget(self.cb_aim_fov)

        aim_key_row = QHBoxLayout()
        self.lbl_aim_key = QLabel(self._aim_key_label_text())
        self.btn_record_aim_key = QPushButton("Record Key")
        self.btn_record_aim_key.clicked.connect(
            lambda: self._start_record_key("aimbot_key", self.lbl_aim_key,
                                            "Aim Key", self.btn_record_aim_key))
        self.btn_clear_aim_key = QPushButton("Clear")
        self.btn_clear_aim_key.setToolTip("Remove the bind: Aimbot fires whenever Aimbot Enabled is on")
        self.btn_clear_aim_key.clicked.connect(self._clear_aim_key)
        aim_key_row.addWidget(self.lbl_aim_key)
        aim_key_row.addWidget(self.btn_record_aim_key)
        aim_key_row.addWidget(self.btn_clear_aim_key)
        layout.addLayout(aim_key_row)

        layout.addLayout(self._slider_row("FOV Radius:", "aimbot_fov", 10, 600))
        layout.addLayout(self._slider_row("Strength:", "aimbot_strength", 1, 100, scale=100))
        layout.addLayout(self._slider_row("Target Offset:", "aimbot_target_offset", -200, 200, as_float=True))

        settings_row = QHBoxLayout()
        self.btn_save_settings = QPushButton("Save Settings")
        self.btn_save_settings.clicked.connect(self._save_settings)
        self.btn_load_settings = QPushButton("Load Settings")
        self.btn_load_settings.clicked.connect(self._load_settings)
        settings_row.addWidget(self.btn_save_settings)
        settings_row.addWidget(self.btn_load_settings)
        layout.addLayout(settings_row)

        self.lbl_settings_status = QLabel(" ")
        self.lbl_settings_status.setStyleSheet("color: #888; font-size: 10px;")
        layout.addWidget(self.lbl_settings_status)

        hint = QLabel("Insert / F1 to toggle menu")
        hint.setStyleSheet("color: #888; font-size: 10px;")
        layout.addWidget(hint)

        container.setFixedWidth(260)

        outer = QVBoxLayout(self)
        outer.addWidget(container)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSizeConstraint(QVBoxLayout.SetFixedSize)
        self.setLayout(outer)

    def _chk(self, text, attr):
        cb = QCheckBox(text)
        cb.setChecked(getattr(self.config, attr))
        cb.stateChanged.connect(lambda s, a=attr: setattr(self.config, a, bool(s)))
        self._bound_checks.append((cb, attr))
        return cb

    def _slider_row(self, label_text, attr, min_val, max_val, scale=1, as_float=False):
        """A label + slider + live value readout, bound to a Config attribute.

        The slider itself only moves in integers, so fractional attrs (like
        aimbot_strength, 0.01-1.0) use `scale` to map slider units back to
        real units (e.g. scale=100 -> slider 1..100 becomes value 0.01..1.00).
        """
        row = QHBoxLayout()
        row.addWidget(QLabel(label_text))

        slider = QSlider(Qt.Horizontal)
        slider.setRange(min_val, max_val)
        slider.setValue(int(round(getattr(self.config, attr) * scale)))

        value_label = QLabel()
        value_label.setMinimumWidth(42)
        value_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        def apply(v):
            real = (v / scale) if scale != 1 else (float(v) if as_float else v)
            setattr(self.config, attr, real)
            value_label.setText(f"{real:.2f}" if scale != 1 else str(int(real)))

        slider.valueChanged.connect(apply)
        apply(slider.value())
        self._bound_sliders.append((slider, attr, scale, apply))

        row.addWidget(slider)
        row.addWidget(value_label)
        return row

    def _combo_row(self, label_text, attr, options):
        """options: list of (display_text, stored_value) pairs."""
        row = QHBoxLayout()
        row.addWidget(QLabel(label_text))

        combo = QComboBox()
        for display, _ in options:
            combo.addItem(display)
        current = getattr(self.config, attr)
        idx = next((i for i, (_, v) in enumerate(options) if v == current), 0)
        combo.setCurrentIndex(idx)

        def apply(i):
            setattr(self.config, attr, options[i][1])

        combo.currentIndexChanged.connect(apply)
        self._bound_combos.append((combo, attr, options))

        row.addWidget(combo)
        return row

    def _pick_enemy_color(self):
        c = QColorDialog.getColor(QColor(*self.config.enemy_color), self)
        if c.isValid():
            self.config.enemy_color = (c.red(), c.green(), c.blue())

    def _pick_local_color(self):
        c = QColorDialog.getColor(QColor(*self.config.local_color), self)
        if c.isValid():
            self.config.local_color = (c.red(), c.green(), c.blue())

    def _start_record_key(self, config_attr, label_widget, label_prefix, button_widget):
        button_widget.setEnabled(False)
        button_widget.setText("Press any key...")
        self._record_start = ctypes.windll.kernel32.GetTickCount()
        self._record_timer = QTimer(self)
        self._record_timer.timeout.connect(
            lambda: self._poll_record_key(config_attr, label_widget, label_prefix, button_widget))
        self._record_timer.start(50)

    def _poll_record_key(self, config_attr, label_widget, label_prefix, button_widget):
        elapsed = ctypes.windll.kernel32.GetTickCount() - self._record_start
        # Ignore the first 300 ms so the click on the record button isn't captured.
        if elapsed < 300:
            return
        for vk in range(1, 0x100):
            if ctypes.windll.user32.GetAsyncKeyState(vk) & 0x8000:
                name = KEY_NAMES.get(vk, f"VK_{vk:02X}")
                setattr(self.config, config_attr, name)
                label_widget.setText(f"{label_prefix}: {name}")
                self._record_timer.stop()
                button_widget.setEnabled(True)
                button_widget.setText("Record Key")
                return
        if elapsed > 5000:
            self._record_timer.stop()
            button_widget.setEnabled(True)
            button_widget.setText("Record Key")

    def _aim_key_label_text(self):
        key = self.config.aimbot_key
        return f"Aim Key: {key}" if key else "Aim Key: (none - always on)"

    def _clear_aim_key(self):
        self.config.aimbot_key = ""
        self.lbl_aim_key.setText(self._aim_key_label_text())

    def _save_settings(self):
        if save_config(self.config):
            self.lbl_settings_status.setText(f"Saved to {os.path.basename(CONFIG_PATH)}")
        else:
            self.lbl_settings_status.setText("Save failed")

    def _load_settings(self):
        if load_config(self.config):
            self._refresh_from_config()
            self.lbl_settings_status.setText(f"Loaded {os.path.basename(CONFIG_PATH)}")
        else:
            self.lbl_settings_status.setText("No saved settings found")

    def _refresh_from_config(self):
        """Sync every bound widget's displayed state after config changes
        externally (i.e. after Load Settings), without rebuilding the UI."""
        for cb, attr in self._bound_checks:
            cb.blockSignals(True)
            cb.setChecked(getattr(self.config, attr))
            cb.blockSignals(False)
        for slider, attr, scale, apply_fn in self._bound_sliders:
            v = int(round(getattr(self.config, attr) * scale))
            slider.blockSignals(True)
            slider.setValue(v)
            slider.blockSignals(False)
            apply_fn(v)
        for combo, attr, options in self._bound_combos:
            current = getattr(self.config, attr)
            idx = next((i for i, (_, v) in enumerate(options) if v == current), 0)
            combo.blockSignals(True)
            combo.setCurrentIndex(idx)
            combo.blockSignals(False)
        self.lbl_toggle_key.setText(f"ESP Toggle Key: {self.config.toggle_key}")
        self.lbl_aim_key.setText(self._aim_key_label_text())

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_pos = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if self._drag_pos is not None and event.buttons() == Qt.LeftButton:
            self.move(event.globalPos() - self._drag_pos)
            event.accept()

    def mouseReleaseEvent(self, event):
        self._drag_pos = None


# ---------------------------------------------------------------------------
# Overlay
# ---------------------------------------------------------------------------
class Overlay(QWidget):
    AIM_MAX_STEP_DEG = 20.0  # hard per-frame aimbot turn-rate cap; see _aim_at()

    def __init__(self, esp: MecchaESP, config: Config, menu: Menu):
        super().__init__()
        self.esp = esp
        self.config = config
        self.menu = menu
        self.setWindowFlags(
            Qt.FramelessWindowHint
            | Qt.WindowStaysOnTopHint
            | Qt.Tool
            | Qt.WindowTransparentForInput
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setWindowTitle("MECCHA ESP")

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_overlay)
        self.timer.start(16)

        self.game_hwnd = self._find_game_window()
        self._resize_to_game()

    def _find_game_window(self):
        try:
            import win32gui
            return win32gui.FindWindow(None, "Chameleon  ")
        except Exception:
            return 0

    def _resize_to_game(self):
        try:
            import win32gui
            if self.game_hwnd:
                rect = win32gui.GetClientRect(self.game_hwnd)
                tl = win32gui.ClientToScreen(self.game_hwnd, (rect[0], rect[1]))
                br = win32gui.ClientToScreen(self.game_hwnd, (rect[2], rect[3]))
                self.setGeometry(tl[0], tl[1], br[0] - tl[0], br[1] - tl[1])
            else:
                self.setGeometry(0, 0, 1920, 1080)
        except Exception:
            self.setGeometry(0, 0, 1920, 1080)

    def update_overlay(self):
        self._resize_to_game()
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        font = QFont("Consolas", 10)
        painter.setFont(font)

        w = self.width()
        h = self.height()

        if not self.config.enabled:
            painter.setPen(QPen(QColor(255, 255, 255)))
            painter.drawText(10, 20, "ESP OFF")
            return

        cam = self.esp.get_camera()
        if not cam:
            painter.setPen(QPen(QColor(255, 255, 255)))
            painter.drawText(10, 20, "NO CAMERA")
            return

        count = 0
        for is_local, pos, idx, name, actor in self.esp.iter_players(
                include_local=self.config.show_local):
            screen_info = self._project_dot(pos, cam, w, h)
            if not screen_info:
                continue
            sx, sy = screen_info
            color = self.config.local_color if is_local else self.config.enemy_color

            label_anchor = (sx, sy)
            if self.config.box_esp:
                style = self.config.marker_style
                if style == "skeleton":
                    skeleton = self.esp.get_skeleton_world_positions(actor)
                    head_screen = self._draw_real_skeleton(painter, skeleton, cam, w, h, color) \
                        if skeleton else None
                    if head_screen:
                        label_anchor = head_screen
                    else:
                        # Real bone data unavailable for this actor this frame
                        # (e.g. mesh not yet streamed in) -- fall back to the
                        # proportioned approximation rather than drawing nothing.
                        outline = self._project_outline(pos, cam, w, h)
                        if outline:
                            top, bottom = outline
                            self._draw_skeleton(painter, top, bottom, color)
                            label_anchor = (bottom[0], top[1])
                elif style == "box":
                    outline = self._project_outline(pos, cam, w, h)
                    if outline:
                        top, bottom = outline
                        self._draw_outline(painter, top, bottom, color)
                        label_anchor = (bottom[0], top[1])
                else:
                    self._draw_dot(painter, sx, sy, color)

            if self.config.snap_lines:
                painter.setPen(QPen(QColor(*color), 1))
                painter.drawLine(int(w / 2), int(h), int(sx), int(sy))

            label_parts = []
            if self.config.show_names:
                label_parts.append(name)
            if self.config.show_distance:
                d = int(dist(pos, cam["loc"]) / 100)
                label_parts.append(f"{d}m")
            if label_parts:
                painter.setPen(QPen(QColor(*color)))
                text = " | ".join(label_parts)
                lx, ly = label_anchor
                painter.drawText(int(lx + self.config.dot_radius + 4), int(ly), text)

            count += 1

        painter.setPen(QPen(QColor(255, 255, 255)))
        painter.drawText(10, 20, f"Players: {count}")
        if self.config.show_debug:
            stats = getattr(self.esp, "_last_iter_stats", {})
            line = (f"PA:{stats.get('pa_total', 0)}/{stats.get('pa_valid', 0)} "
                    f"LA:{stats.get('level_total', 0)}/{stats.get('level_valid', 0)}")
            painter.drawText(10, 35, line)

        # ------------------------------------------------------------------
        # Aimbot
        # ------------------------------------------------------------------
        if self.config.aimbot_enabled:
            cx, cy = w / 2, h / 2
            if self.config.aimbot_show_fov:
                painter.setPen(QPen(QColor(255, 255, 255), 1))
                painter.setBrush(Qt.NoBrush)
                painter.drawEllipse(int(cx - self.config.aimbot_fov),
                                    int(cy - self.config.aimbot_fov),
                                    self.config.aimbot_fov * 2,
                                    self.config.aimbot_fov * 2)

            best_target = self._find_best_target(cam, w, h)
            if best_target and self._aim_key_held():
                pitch_offset, yaw_offset = best_target
                self._aim_at(pitch_offset, yaw_offset, cam)

    def _project_dot(self, center_pos, camera, screen_w, screen_h):
        # The actor's RootComponent relative location is already the capsule center,
        # so project it directly instead of guessing from feet/head.
        s = w2s(center_pos, camera, screen_w, screen_h)
        if not s:
            return None
        return (s[0], s[1] + self.config.box_y_offset)

    def _draw_dot(self, painter, cx, cy, color):
        r = self.config.dot_radius
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(*color))
        painter.drawEllipse(int(cx - r), int(cy - r), r * 2, r * 2)

    def _project_outline(self, center_pos, camera, screen_w, screen_h):
        """Project the head and feet of the capsule to screen space."""
        half = self.config.box_height_world / 2.0
        top_world = (center_pos[0], center_pos[1], center_pos[2] + half)
        bottom_world = (center_pos[0], center_pos[1], center_pos[2] - half)
        top = w2s(top_world, camera, screen_w, screen_h)
        bottom = w2s(bottom_world, camera, screen_w, screen_h)
        if not top or not bottom:
            return None
        yoff = self.config.box_y_offset
        return (top[0], top[1] + yoff), (bottom[0], bottom[1] + yoff)

    def _draw_outline(self, painter, top, bottom, color):
        tx, ty = top
        bx, by = bottom
        height = by - ty
        if height <= 1:
            return
        width = height * 0.42  # rough human width/height ratio
        cx = (tx + bx) / 2.0
        painter.setPen(QPen(QColor(*color), 2))
        painter.setBrush(Qt.NoBrush)
        painter.drawRect(int(cx - width / 2.0), int(ty), int(width), int(height))

    def _draw_real_skeleton(self, painter, skeleton, camera, screen_w, screen_h, color):
        """Draw the actual per-bone skeleton (see MecchaESP.get_skeleton_world_positions)
        by projecting each bone's real world position to screen and connecting
        it to its real parent bone -- not an approximation. Returns the
        screen position of the head bone (for label placement), or None if
        nothing projected on screen this frame."""
        yoff = self.config.box_y_offset
        screen_points = {}
        for bone_name, (world_pos, _parent) in skeleton.items():
            s = w2s(world_pos, camera, screen_w, screen_h)
            if s:
                screen_points[bone_name] = (s[0], s[1] + yoff)

        painter.setPen(QPen(QColor(*color), 2))
        painter.setBrush(Qt.NoBrush)
        for bone_name, (_, parent_name) in skeleton.items():
            if bone_name not in screen_points or parent_name not in screen_points:
                continue
            x1, y1 = screen_points[parent_name]
            x2, y2 = screen_points[bone_name]
            painter.drawLine(int(x1), int(y1), int(x2), int(y2))

        for label in ("Head", "head_end"):
            if label in screen_points:
                return screen_points[label]
        return next(iter(screen_points.values()), None)

    def _draw_skeleton(self, painter, top, bottom, color):
        """Fallback stylized stick-figure outline, used only when real bone
        data isn't available for an actor this frame (see _draw_real_skeleton
        for the primary path). Derived from the same head/feet screen points
        as the box outline -- a proportioned approximation, same spirit as
        the box outline being a bounding box rather than a true mesh."""
        tx, ty = top
        bx, by = bottom
        height = by - ty
        if height <= 1:
            return
        width = height * 0.42
        cx = (tx + bx) / 2.0

        head_r = height * 0.09
        head_cy = ty + head_r
        neck_y = ty + height * 0.20
        hip_y = ty + height * 0.55
        hand_y = neck_y + height * 0.28
        shoulder_half = width * 0.5
        foot_half = width * 0.35

        painter.setPen(QPen(QColor(*color), 2))
        painter.setBrush(Qt.NoBrush)

        painter.drawEllipse(int(cx - head_r), int(head_cy - head_r), int(head_r * 2), int(head_r * 2))
        painter.drawLine(int(cx), int(neck_y), int(cx), int(hip_y))  # spine
        painter.drawLine(int(cx - shoulder_half), int(hand_y), int(cx), int(neck_y))  # left arm
        painter.drawLine(int(cx + shoulder_half), int(hand_y), int(cx), int(neck_y))  # right arm
        painter.drawLine(int(cx - foot_half), int(by), int(cx), int(hip_y))  # left leg
        painter.drawLine(int(cx + foot_half), int(by), int(cx), int(hip_y))  # right leg

    # -----------------------------------------------------------------------
    # Aimbot helpers
    # -----------------------------------------------------------------------
    def _aim_key_held(self):
        key = self.config.aimbot_key
        if not key:
            # Keyless: fires continuously whenever Aimbot Enabled is on.
            return True
        vk = KEY_VK.get(key, 0x06)
        return bool(ctypes.windll.user32.GetAsyncKeyState(vk) & 0x8000)

    def _find_best_target(self, camera, screen_w, screen_h):
        # Extra self-filter: iter_players should skip local, but if local controller
        # resolution fails it can leak through. Skip anything close to the camera
        # or to the local pawn.
        world = self.esp._get_world()
        local_pc = self.esp._get_local_controller(world) if world else 0
        local_pawn = rp(self.esp.pm, local_pc + self.esp.offsets["APlayerController::AcknowledgedPawn"]) if local_pc else 0
        local_pos = self.esp._actor_position(local_pawn) if local_pawn else None

        cx, cy = screen_w / 2, screen_h / 2
        cam_loc = camera["loc"]

        # If we cannot identify the local player, do not silently aim at anyone
        # (prevents locking onto our own body when controller resolution fails).
        if not local_pawn:
            return None

        best_dist = float("inf")
        best_target = None
        for is_local, pos, idx, name, actor in self.esp.iter_players(include_local=False, players_only=True):
            if is_local:
                continue
            # Skip self if it leaked through. Use a generous threshold because
            # third-person cameras can sit more than 50 cm from the capsule center.
            if local_pos:
                dself = math.sqrt((pos[0] - local_pos[0]) ** 2 +
                                  (pos[1] - local_pos[1]) ** 2 +
                                  (pos[2] - local_pos[2]) ** 2)
                if dself < 150.0:
                    continue
            # Skip anything right on top of the camera (failsafe for broken local filter).
            dcam = math.sqrt((pos[0] - cam_loc[0]) ** 2 +
                             (pos[1] - cam_loc[1]) ** 2 +
                             (pos[2] - cam_loc[2]) ** 2)
            if dcam < 100.0:
                continue

            # Aim at the same point the ESP marker is drawn, plus the user offset.
            aim_pos = (pos[0], pos[1], pos[2] + self.config.aimbot_target_offset)
            s = w2s(aim_pos, camera, screen_w, screen_h)
            if not s:
                continue
            dx = s[0] - cx
            dy = s[1] - cy
            d = math.sqrt(dx * dx + dy * dy)
            if d <= self.config.aimbot_fov and d < best_dist:
                best_dist = d
                # Angular offset (degrees) needed to move this target's screen
                # position to dead-center, derived by inverting w2s()'s own
                # projection math -- see _screen_offset_to_angles().
                best_target = self._screen_offset_to_angles(dx, dy, camera, screen_w, screen_h)
        return best_target

    def _screen_offset_to_angles(self, dx_px, dy_px, camera, screen_w, screen_h):
        """Invert w2s(): convert a screen-space pixel offset from center into
        a (pitch_offset, yaw_offset) in degrees, relative to the camera's own
        current forward direction.

        This is deliberately origin-independent -- it never computes an
        absolute 3D target rotation from a world-space vector. Doing that
        (from the camera's location, or from the local pawn's location)
        requires that origin to exactly match whatever origin ControlRotation
        is really measured from, and any mismatch shows up as a large,
        sudden correction the instant a target crosses into the FOV circle
        (which by definition only happens when the camera is *already*
        pointed close to the target). Working purely in screen-space angles
        sidesteps that mismatch entirely: a target near screen-center always
        yields a small angular delta, no matter where the camera boom sits
        relative to the character.
        """
        fov = camera["fov"]
        aspect = screen_w / screen_h
        tan_hfov = math.tan(math.radians(fov) / 2.0)
        ndc_x = dx_px / (screen_w / 2.0)
        ndc_y = -dy_px / (screen_h / 2.0)  # screen Y grows downward; flip so +ndc_y = up
        yaw_offset = math.degrees(math.atan(ndc_x * tan_hfov))
        pitch_offset = math.degrees(math.atan(ndc_y * tan_hfov / aspect))
        return pitch_offset, yaw_offset

    def _read_control_rotation(self):
        world = self.esp._get_world()
        if not world:
            return None
        pc = self.esp._get_local_controller(world)
        if not pc:
            return None
        addr = pc + self.esp.offsets["AController::ControlRotation"]
        # UE5.6 uses Large World Coordinates: FRotator's Pitch/Yaw/Roll are
        # doubles (8 bytes each), same as the camera rotation read via rvec3()
        # in _read_pov(). Reading these as 4-byte floats (the old UE4 layout)
        # decoded garbage -- that's what was flinging the view around.
        rot = rvec3(self.esp.pm, addr)
        # Reject a torn/garbage read (e.g. mid-replication) instead of using it
        # as the LERP base.
        if any(math.isnan(v) or abs(v) > 1e6 for v in rot):
            if self.config.show_debug:
                print(f"[AIM-DEBUG] rejected bad ControlRotation read: {rot}")
            return None
        return rot

    def _write_control_rotation(self, rot):
        world = self.esp._get_world()
        if not world:
            return False
        pc = self.esp._get_local_controller(world)
        if not pc:
            return False
        addr = pc + self.esp.offsets["AController::ControlRotation"]
        return (wdouble(self.esp.pm, addr, rot[0]) and
                wdouble(self.esp.pm, addr + 8, rot[1]) and
                wdouble(self.esp.pm, addr + 16, rot[2]))

    def _aim_at(self, pitch_offset, yaw_offset, camera):
        if not camera:
            return
        current = self._read_control_rotation()
        if current is None:
            return

        # The absolute target rotation is the camera's *own* current rotation
        # plus the small screen-space angular offset computed in
        # _screen_offset_to_angles() -- not a fresh vector computed from some
        # other origin (camera location or pawn location). Anchoring to the
        # camera's own rotation guarantees the target is only ever a small
        # nudge away, since _find_best_target already required the target to
        # be near screen-center (i.e. near where the camera is already
        # looking) before it could be selected at all.
        cam_pitch, cam_yaw = camera["rot"][0], camera["rot"][1]
        target_pitch = max(-89.9, min(89.9, cam_pitch + pitch_offset))
        target_yaw = (cam_yaw + yaw_offset + 180.0) % 360.0 - 180.0

        strength = self.config.aimbot_strength
        # ControlRotation's raw components can come back wrapped into [0, 360)
        # rather than signed (-180, 180] -- confirmed live: a reported pitch of
        # 348.8 was actually -11.2 (348.8 - 360). Clamping to +-89.9 *before*
        # unwrapping treated that as "almost straight up" instead of "slightly
        # down", which is exactly what was flinging the view upward every time.
        # Unwrap first, then clamp to the physically valid pitch range.
        current_pitch = (current[0] + 180.0) % 360.0 - 180.0
        current_pitch = max(-89.9, min(89.9, current_pitch))

        # Hard per-frame turn-rate cap, independent of strength. This is a
        # structural guarantee against a "jump": whatever target_pitch/yaw
        # turn out to be -- even if some other assumption about this build's
        # memory layout still doesn't hold -- a single frame can never move
        # the view by more than this many degrees. Any residual bug becomes,
        # at worst, a fast-but-continuous turn, never an instantaneous snap.
        pitch_step = max(-self.AIM_MAX_STEP_DEG, min(self.AIM_MAX_STEP_DEG,
                          (target_pitch - current_pitch) * strength))
        new_pitch = max(-89.9, min(89.9, current_pitch + pitch_step))

        # Yaw wraps at +-180 degrees; take the shortest path so it never spins
        # the long way around.
        yaw_delta = (target_yaw - current[1] + 180.0) % 360.0 - 180.0
        yaw_step = max(-self.AIM_MAX_STEP_DEG, min(self.AIM_MAX_STEP_DEG, yaw_delta * strength))
        new_yaw = (current[1] + yaw_step + 180.0) % 360.0 - 180.0

        if self.config.show_debug:
            print(f"[AIM-DEBUG] cam_rot=({cam_pitch:.2f},{cam_yaw:.2f}) "
                  f"offset=({pitch_offset:.2f},{yaw_offset:.2f}) current={current} "
                  f"target=({target_pitch:.2f},{target_yaw:.2f}) "
                  f"step=({pitch_step:.2f},{yaw_step:.2f}) new=({new_pitch:.2f},{new_yaw:.2f})")
        self._write_control_rotation((new_pitch, new_yaw, current[2]))

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def _set_dpi_aware():
    try:
        ctypes.windll.user32.SetProcessDpiAwarenessContext(-4)  # PerMonitorAwareV2
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def _install_keyboard_interrupt_handler():
    # PyQt5 catches exceptions raised inside slots (e.g. this QTimer-driven
    # update_overlay/poll_keys) and routes them through sys.excepthook instead
    # of letting them propagate up through app.exec_() -- so a plain
    # try/except KeyboardInterrupt around main() never sees a Ctrl+C that
    # lands mid-frame. Catching it here, where PyQt actually delivers it, is
    # the fix.
    def _excepthook(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            print("\nHave a great day!")
            QApplication.quit()
            return
        sys.__excepthook__(exc_type, exc_value, exc_tb)
    sys.excepthook = _excepthook


def main():
    _set_dpi_aware()
    _install_keyboard_interrupt_handler()
    app = QApplication(sys.argv)
    config = Config()
    load_config(config)  # silently keeps defaults if esp_config.json doesn't exist yet
    esp = MecchaESP()
    menu = Menu(config)
    overlay = Overlay(esp, config, menu)
    overlay.show()
    menu.show()

    # Poll Insert/F1 globally to toggle menu visibility.
    VK_INSERT = 0x2D
    VK_F1 = 0x70
    _key_states = {"insert": False, "f1": False, "toggle": False}

    def poll_keys():
        for vk, name in [(VK_INSERT, "insert"), (VK_F1, "f1")]:
            state = ctypes.windll.user32.GetAsyncKeyState(vk) & 0x8000
            if state and not _key_states[name]:
                menu.setVisible(not menu.isVisible())
            _key_states[name] = bool(state)

        toggle_vk = KEY_VK.get(config.toggle_key, 0x71)
        state = ctypes.windll.user32.GetAsyncKeyState(toggle_vk) & 0x8000
        if state and not _key_states["toggle"]:
            menu.cb_enabled.setChecked(not menu.cb_enabled.isChecked())
        _key_states["toggle"] = bool(state)

    key_timer = QTimer()
    key_timer.timeout.connect(poll_keys)
    key_timer.start(50)

    sys.exit(app.exec_())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nHave a great day!")
        sys.exit(0)
