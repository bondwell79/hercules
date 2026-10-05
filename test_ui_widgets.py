"""Test that the new UI widgets can be instantiated and rendered."""
import sys
import os

# Add the hercules directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import tkinter as tk
    from tkinter import ttk
    import hercules

    # Create a root window
    root = tk.Tk()
    root.withdraw()  # Hide the window

    # Test RoundedFrame
    frame = hercules.RoundedFrame(
        root,
        bg=hercules.CONFIG.ui_card_bg,
        border_color=hercules.CONFIG.ui_card_border_color,
        border_width=hercules.CONFIG.ui_card_border_width,
        radius=hercules.CONFIG.ui_corner_radius,
        padding=10,
    )
    frame.pack(fill="both", expand=True)
    print("OK: RoundedFrame instantiated")

    # Add a child widget to the inner frame
    ttk.Label(frame.inner, text="Test label").pack()
    print("OK: Child widget added to RoundedFrame.inner")

    # Test RoundedButton
    btn = hercules.RoundedButton(
        root,
        text="Test Button",
        command=lambda: None,
        bg=hercules.CONFIG.ui_button_accent_bg,
        fg=hercules.CONFIG.ui_button_accent_fg,
        hover_bg=hercules.CONFIG.ui_button_accent_hover_bg,
        pressed_bg=hercules.CONFIG.ui_button_accent_pressed_bg,
        radius=hercules.CONFIG.ui_corner_radius,
        font=(hercules.CONFIG.ui_font_family, hercules.CONFIG.ui_font_size, "bold"),
        padding_x=14,
        padding_y=6,
    )
    btn.pack()
    print("OK: RoundedButton instantiated")

    # Test configure method
    btn.configure(text="Updated Text")
    assert btn.canvas.itemcget(btn._text_id, "text") == "Updated Text", "Text not updated"
    print("OK: RoundedButton.configure(text=...) works")

    btn._anim_ms = 0
    btn.configure(state="disabled")
    assert btn._disabled == True, "Disabled state not set"
    assert btn._current_color == btn._disabled_bg, "Disabled button color not applied"
    print("OK: RoundedButton.configure(state='disabled') works")

    btn.configure(state="normal")
    assert btn._disabled == False, "Normal state not set"
    assert btn._current_color == btn._bg, "Normal button color not restored"
    print("OK: RoundedButton.configure(state='normal') works")

    # Test GradientCanvas
    canvas = hercules.GradientCanvas(
        root,
        color_top=hercules.CONFIG.ui_context_bar_bg,
        color_bottom=hercules.CONFIG.ui_context_bar_bg,
        radius=hercules.CONFIG.ui_corner_radius,
        height=16,
    )
    canvas.pack(fill="x")
    print("OK: GradientCanvas instantiated")

    # Test _draw_rounded_rect helper
    test_canvas = tk.Canvas(root, width=100, height=50)
    test_canvas.pack()
    hercules._draw_rounded_rect(
        test_canvas, 0, 0, 100, 50, radius=10, fill="#ff0000", outline=""
    )
    print("OK: _draw_rounded_rect works")

    # Update the window to process all pending events
    root.update_idletasks()
    root.update()

    # Clean up
    root.destroy()

    print("\nAll UI widget tests passed!")
except Exception as e:
    print(f"FAIL: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
