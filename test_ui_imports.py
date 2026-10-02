"""Test that the new UI widgets can be imported and instantiated."""
import sys
import os

# Add the hercules directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import hercules
    print("OK: hercules module imported successfully")

    # Check that the new widgets exist
    assert hasattr(hercules, "RoundedFrame"), "RoundedFrame not found"
    assert hasattr(hercules, "RoundedButton"), "RoundedButton not found"
    assert hasattr(hercules, "GradientCanvas"), "GradientCanvas not found"
    assert hasattr(hercules, "_draw_rounded_rect"), "_draw_rounded_rect not found"
    print("OK: All new widgets are defined")

    # Check that the new config options exist
    config = hercules.CONFIG
    assert hasattr(config, "ui_corner_radius"), "ui_corner_radius not found"
    assert hasattr(config, "ui_card_border_width"), "ui_card_border_width not found"
    assert hasattr(config, "ui_card_border_color"), "ui_card_border_color not found"
    assert hasattr(config, "ui_accent_color"), "ui_accent_color not found"
    assert hasattr(config, "ui_window_alpha"), "ui_window_alpha not found"
    assert hasattr(config, "ui_button_accent_bg"), "ui_button_accent_bg not found"
    assert hasattr(config, "ui_button_accent_fg"), "ui_button_accent_fg not found"
    assert hasattr(config, "ui_button_accent_hover_bg"), "ui_button_accent_hover_bg not found"
    assert hasattr(config, "ui_button_accent_pressed_bg"), "ui_button_accent_pressed_bg not found"
    assert hasattr(config, "ui_button_hover_bg"), "ui_button_hover_bg not found"
    assert hasattr(config, "ui_button_pressed_bg"), "ui_button_pressed_bg not found"
    assert hasattr(config, "ui_button_danger_bg"), "ui_button_danger_bg not found"
    assert hasattr(config, "ui_button_danger_fg"), "ui_button_danger_fg not found"
    assert hasattr(config, "ui_button_danger_hover_bg"), "ui_button_danger_hover_bg not found"
    assert hasattr(config, "ui_button_danger_pressed_bg"), "ui_button_danger_pressed_bg not found"
    # Opciones de barra de título moderna (Windows 10/11 vía DWM).
    assert hasattr(config, "ui_titlebar_style"), "ui_titlebar_style not found"
    assert hasattr(config, "ui_titlebar_color"), "ui_titlebar_color not found"
    assert hasattr(config, "ui_titlebar_text_color"), "ui_titlebar_text_color not found"
    assert config.ui_titlebar_style in {"system", "dark", "accent", "custom"}, \
        f"ui_titlebar_style invalid: {config.ui_titlebar_style}"
    print("OK: All new config options are defined")

    # Check that the values are reasonable
    assert 0 <= config.ui_corner_radius <= 30, f"ui_corner_radius out of range: {config.ui_corner_radius}"
    assert 0.5 <= config.ui_window_alpha <= 1.0, f"ui_window_alpha out of range: {config.ui_window_alpha}"
    print(f"OK: Config values are valid (corner_radius={config.ui_corner_radius}, window_alpha={config.ui_window_alpha})")

    print("\nAll UI import tests passed!")
except Exception as e:
    print(f"FAIL: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
