"""Test that the modern title bar helper works correctly."""
import sys
import os

# Add the hercules directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import hercules
    print("OK: hercules module imported successfully")

    # Check that the helper function exists
    assert hasattr(hercules, "_apply_modern_titlebar"), \
        "_apply_modern_titlebar not found"
    print("OK: _apply_modern_titlebar function is defined")

    # Check that the helper accepts a window argument
    import inspect
    sig = inspect.signature(hercules._apply_modern_titlebar)
    assert "window" in sig.parameters, \
        "_apply_modern_titlebar must accept a 'window' parameter"
    print("OK: _apply_modern_titlebar accepts a 'window' parameter")

    # Verify the function is callable and doesn't crash on a fake window
    class FakeWindow:
        def frame(self):
            raise RuntimeError("no real frame")

        def winfo_id(self):
            return 0

    # Should not raise (it should silently ignore errors).
    hercules._apply_modern_titlebar(FakeWindow())
    print("OK: _apply_modern_titlebar handles fake window gracefully")

    # Verify the config options are accessible
    config = hercules.CONFIG
    style = config.ui_titlebar_style
    color = config.ui_titlebar_color
    text_color = config.ui_titlebar_text_color
    print(f"OK: Config values: style={style!r}, color={color!r}, text_color={text_color!r}")

    # Verify the default style is one of the valid options
    assert style in {"system", "dark", "accent", "custom"}, \
        f"Invalid default style: {style}"
    print(f"OK: Default style {style!r} is valid")

    print("\nAll modern title bar tests passed!")
except Exception as e:
    print(f"FAIL: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
