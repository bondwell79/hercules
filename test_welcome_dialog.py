"""Test that the WelcomeDialog works correctly."""
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
    root.title("Test Root")
    root.geometry("800x600")

    # Create the welcome dialog
    dialog = hercules.WelcomeDialog(root)

    # Update the window to process all pending events
    root.update_idletasks()
    root.update()

    # Verify the dialog window size
    print(f"Dialog window size: {dialog.window.winfo_width()}x{dialog.window.winfo_height()}")
    print(f"Dialog reqwidth: {dialog.window.winfo_reqwidth()}")
    print(f"Dialog reqheight: {dialog.window.winfo_reqheight()}")

    # Verify that the dialog has a reasonable size
    assert dialog.window.winfo_reqwidth() > 400, "Dialog is too narrow"
    assert dialog.window.winfo_reqheight() > 300, "Dialog is too short"

    # Verify the outer RoundedFrame
    print(f"Outer frame size: {dialog.window.winfo_width()}x{dialog.window.winfo_height()}")

    print("\nWelcomeDialog test passed!")

    # Clean up
    dialog.window.destroy()
    root.destroy()
except Exception as e:
    print(f"FAIL: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
