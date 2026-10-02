"""Test that the UI layout works correctly with realistic content."""
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
    root.title("Test Dashboard")
    root.geometry("1200x800")
    root.configure(bg=hercules.CONFIG.ui_bg_color)

    # Simulate the dashboard layout
    # Top zone: prompt + buttons
    top = ttk.Frame(root, padding=10)
    top.pack(side="top", fill="x")

    ttk.Label(top, text="📝 Nueva instrucción para el agente").pack(anchor="w")

    prompt_card = hercules.RoundedFrame(
        top,
        bg=hercules.CONFIG.ui_prompt_bg,
        border_color=hercules.CONFIG.ui_card_border_color,
        border_width=hercules.CONFIG.ui_card_border_width,
        radius=hercules.CONFIG.ui_corner_radius,
        padding=2,
    )
    prompt_card.pack(fill="x", pady=(6, 6))

    prompt_text = tk.Text(
        prompt_card.inner,
        height=4,
        wrap="word",
        font=(hercules.CONFIG.ui_mono_font_family, hercules.CONFIG.ui_mono_font_size),
        relief="flat",
        borderwidth=0,
        background=hercules.CONFIG.ui_prompt_bg,
        foreground=hercules.CONFIG.ui_prompt_fg,
        highlightthickness=0,
        padx=8,
        pady=6,
    )
    prompt_text.pack(fill="both", expand=True)
    prompt_text.insert("1.0", "Test prompt content")

    btn_row = ttk.Frame(top)
    btn_row.pack(fill="x")

    btn1 = hercules.RoundedButton(
        btn_row,
        text="▶ Ejecutar",
        command=lambda: None,
        bg=hercules.CONFIG.ui_button_accent_bg,
        fg=hercules.CONFIG.ui_button_accent_fg,
        hover_bg=hercules.CONFIG.ui_button_accent_hover_bg,
        pressed_bg=hercules.CONFIG.ui_button_accent_pressed_bg,
        radius=hercules.CONFIG.ui_corner_radius,
        font=(hercules.CONFIG.ui_font_family, hercules.CONFIG.ui_font_size, "bold"),
        padding_x=18,
        padding_y=8,
    )
    btn1.pack(side="left")

    btn2 = hercules.RoundedButton(
        btn_row,
        text="🧹 Limpiar",
        command=lambda: None,
        bg=hercules.CONFIG.ui_button_bg,
        fg=hercules.CONFIG.ui_button_fg,
        hover_bg=hercules.CONFIG.ui_button_hover_bg,
        pressed_bg=hercules.CONFIG.ui_button_pressed_bg,
        radius=hercules.CONFIG.ui_corner_radius,
        padding_x=14,
        padding_y=6,
    )
    btn2.pack(side="left", padx=(8, 0))

    # Middle zone: two columns
    middle = ttk.Frame(root, padding=(10, 0))
    middle.pack(side="top", fill="both", expand=True)
    middle.columnconfigure(0, weight=1)
    middle.columnconfigure(1, weight=1)
    middle.rowconfigure(0, weight=1)

    left = hercules.RoundedFrame(
        middle,
        bg=hercules.CONFIG.ui_card_bg,
        border_color=hercules.CONFIG.ui_card_border_color,
        border_width=hercules.CONFIG.ui_card_border_width,
        radius=hercules.CONFIG.ui_corner_radius,
        padding=10,
    )
    left.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

    ttk.Label(left.inner, text="Pendientes y en ejecución").pack(anchor="w")
    ttk.Label(left.inner, text="Tarea 1: En progreso").pack(anchor="w", pady=2)
    ttk.Label(left.inner, text="Tarea 2: Pendiente").pack(anchor="w", pady=2)

    right = hercules.RoundedFrame(
        middle,
        bg=hercules.CONFIG.ui_card_bg,
        border_color=hercules.CONFIG.ui_card_border_color,
        border_width=hercules.CONFIG.ui_card_border_width,
        radius=hercules.CONFIG.ui_corner_radius,
        padding=10,
    )
    right.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

    ttk.Label(right.inner, text="Ejecutadas / Históricas").pack(anchor="w")
    ttk.Label(right.inner, text="Tarea 3: Completada").pack(anchor="w", pady=2)

    # Update the window to process all pending events
    root.update_idletasks()
    root.update()

    # Verify sizes
    print(f"Root window size: {root.winfo_width()}x{root.winfo_height()}")
    print(f"Prompt card size: {prompt_card.canvas.winfo_width()}x{prompt_card.canvas.winfo_height()}")
    print(f"Button 1 size: {btn1.canvas.winfo_width()}x{btn1.canvas.winfo_height()}")
    print(f"Button 2 size: {btn2.canvas.winfo_width()}x{btn2.canvas.winfo_height()}")
    print(f"Left card size: {left.canvas.winfo_width()}x{left.canvas.winfo_height()}")
    print(f"Right card size: {right.canvas.winfo_width()}x{right.canvas.winfo_height()}")

    # Verify that the cards have reasonable sizes (not collapsed)
    assert prompt_card.canvas.winfo_width() > 100, "Prompt card is too small"
    assert prompt_card.canvas.winfo_height() > 50, "Prompt card is too small"
    assert btn1.canvas.winfo_width() > 50, "Button 1 is too small"
    assert btn1.canvas.winfo_height() > 20, "Button 1 is too small"
    assert left.canvas.winfo_width() > 100, "Left card is too small"
    assert left.canvas.winfo_height() > 50, "Left card is too small"
    assert right.canvas.winfo_width() > 100, "Right card is too small"
    assert right.canvas.winfo_height() > 50, "Right card is too small"

    print("\nAll layout tests passed!")

    # Clean up
    root.destroy()
except Exception as e:
    print(f"FAIL: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
