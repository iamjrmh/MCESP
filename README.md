# MCESP - MECCHA CHAMELEON External ESP + Aimbot

A fully external ESP and aimbot for **MECCHA CHAMELEON** (Steam / UE5.6). No DLL injection into the game, no UE4SS dependency - it pattern-scans the running game process and reads (and, for the aimbot, writes a small amount of) memory through `pymem`.

## Features

The menu is organized into four tabs: **ESP**, **Aimbot**, **Movement**, **Settings**.

**ESP**
- Player Marker with 3 styles: **Dot**, **Box Outline**, or **Skeleton** (a real bone-driven skeleton, not an approximation - it's built from the game's actual live bone poses and hierarchy)
- Show/hide local player, names, distance, snap lines, debug counters
- Separate enemy/local marker colors (color pickers)
- Adjustable dot radius, model height, Y offset - all sliders
- Real player names pulled from the game, not placeholder text
- Overlay tracks the game window's actual position/size live, so it stays lined up through window moves, resizes, and borderless-fullscreen changes

**Aimbot**
- Adjustable FOV circle and **Strength** (how snappy vs. smooth the aim-assist is)
- Adjustable target offset (aim at center mass by default, raise for head/chest)
- Rebindable aim key, or **keyless mode** - clear the bind and it aims continuously whenever Aimbot Enabled is checked, no key needed
- Hard-capped turn rate - it can't instantly snap your view, even in edge cases

**Movement**
- **Fly**: rebindable up/down keys, hovers cleanly instead of drifting on release. Safe to use during the actual challenge - it doesn't make you untouchable.
- **Noclip**: full wall passthrough. Only works while in the game's own Free Camera / Free Movement mode (spectate). Solo exploring only - don't use it around other players.
- **Movement Speed**: one slider that scales walking, sprinting, and flying speed together.
- **Force Spectate**: rebindable hotkey that puts you straight into full free-camera spectate from anywhere - any role, in a match or still in the lobby - without needing to manually press 5 then 4. Unbound by default; bind it here.

**Quality of life**
- Everything above is a slider/checkbox/dropdown in an in-game menu, no config file editing needed
- **Save Settings** / **Load Settings** buttons - your setup also auto-loads on the next launch
- Rebindable menu-toggle key and aimbot key (click "Record Key", press anything)
- **RGB Mode** (Settings tab) - fun toggle that cycles all the colored UI/ESP elements through a rainbow
- Ctrl+C in the terminal exits cleanly

## Requirements

- Windows 10/11
- Python 3.11+
- Game running in windowed/borderless mode

```bash
pip install pymem PyQt5 pywin32
```

## Usage


1. Run MCESP.exe - It'll print `Waiting on game...` if the game isn't open yet, then wait for it. Once found: `Waiting on injection...` then `Injected` - this is just it attaching to read memory, not actually injecting anything into the game.
2. Open MECCHA Chameleon
3. A transparent overlay appears over the game window, plus a settings menu.
4. Configure everything from the menu, then optionally hit **Save Settings** so it's there next time.
5. Press INSERT to open/close the Menu

OR

1. Launch MECCHA CHAMELEON and get into a match/lobby.
2. Run:
   ```bash
   python MCESP.py
   ```
3. It'll print `Waiting on game...` if the game isn't open yet, then wait for it. Once found: `Waiting on injection...` then `Injected` - this is just it attaching to read memory, not actually injecting anything into the game.
4. A transparent overlay appears over the game window, plus a settings menu.
5. Configure everything from the menu, then optionally hit **Save Settings** so it's there next time.

## Keybinds (all rebindable in the menu)

| Key | Action |
|---|---|
| `Insert` or `F1` | Show/hide the settings menu |
| `F2` (default) | Toggle ESP on/off |
| `MB5` (default) | Hold to aim (if a key is bound). Clear it in the menu for always-on aimbot |
| `Space` (default) | Fly up (while Fly Enabled is checked) |
| `Ctrl` (default) | Fly down (while Fly Enabled is checked) |
| Unbound by default | Force Spectate |
| `Ctrl+C` (in terminal) | Quit |

To rebind any of these: click **Record Key** next to it in the menu (ESP toggle and aim key are in their own tabs; Fly and Force Spectate keys are in the Movement tab), then press any key/mouse button. Click **Clear** next to the aim key or Force Spectate key to unbind.

> The ESP reads `GameState -> PlayerArray` for other players - you need to actually be in a match/lobby with someone else for enemy markers to show up. Enable **Show Local Player** in the menu to sanity-check the overlay/projection is working even by yourself.

## Notes / troubleshooting

- Everything except a couple of specific offsets is found dynamically via the engine's own reflection data, so it should keep working across most game patches. The **skeleton marker specifically** relies on two hardcoded offsets (bone pose cache + bone name table) found by manually scanning this exact game build (5.6.1) - if a future update breaks *only* the skeleton view (dot/box still fine), that's why; ping whoever set this up to re-find them.
- **Force Spectate** calls the game's own internal functions directly rather than pretending to press a key - it should keep working across patches the same way most of the tool does (the functions it calls are found dynamically each session), except one small hardcoded flag check it uses to avoid re-toggling free-cam back off if you press the key twice. Worst case if that ever breaks: the key still forces you into spectate/free-cam fine, it just might toggle free-cam off if you press it again while already in it.
- The script expects the game window title `Chameleon  `. If that ever changes, `Overlay._find_game_window()` needs updating.
- Settings save to `Documents\MCESP\esp_config.json` - shared between the compiled `.exe` and the source version, so switching between them (or updating one) doesn't lose your setup.

## Disclaimer

This project is provided for **educational and research purposes only**, intended for private, consensual matches with friends. Using cheats or unauthorized third-party tools in online games may violate the game's Terms of Service and can result in account suspension or permanent ban. The authors assume no liability for any damages, bans, or other consequences resulting from the use or misuse of this software. Use at your own risk, and only with people who know it's running.
