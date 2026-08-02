from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk
from typing import Callable

from .agent import AdvancedGeminiAI
from .gemini import DEFAULT_MODEL
from .memory import MemoryHit, ObsidianMemory


Worker = Callable[[], str]


def format_hit(hit: MemoryHit) -> str:
    return f"{hit.score:.2f}  {hit.title}\n{hit.path}\n"


class AssistantGUI:
    """Tkinter desktop GUI for the Obsidian Gemini assistant."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Obsidian Gemini AI")
        self.events: queue.Queue[tuple[str, str]] = queue.Queue()
        self.vault_var = tk.StringVar(value="memory_vault")
        self.model_var = tk.StringVar(value=DEFAULT_MODEL)
        self.reflect_var = tk.BooleanVar(value=False)
        self.deep_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Ready")
        self._build_layout()
        self._poll_events()

    def _build_layout(self) -> None:
        outer = ttk.Frame(self.root, padding=12)
        outer.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        outer.columnconfigure(1, weight=1)
        outer.rowconfigure(3, weight=1)
        outer.rowconfigure(5, weight=1)

        ttk.Label(outer, text="Vault").grid(row=0, column=0, sticky="w")
        ttk.Entry(outer, textvariable=self.vault_var).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(outer, text="Browse", command=self._browse_vault).grid(row=0, column=2, sticky="ew")

        ttk.Label(outer, text="Model").grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Entry(outer, textvariable=self.model_var).grid(row=1, column=1, sticky="ew", padx=6, pady=(6, 0))
        flags = ttk.Frame(outer)
        flags.grid(row=1, column=2, sticky="w", pady=(6, 0))
        ttk.Checkbutton(flags, text="Reflect", variable=self.reflect_var).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(flags, text="Deep", variable=self.deep_var).grid(row=0, column=1, sticky="w", padx=(8, 0))

        controls = ttk.Frame(outer)
        controls.grid(row=2, column=0, columnspan=3, sticky="ew", pady=8)
        controls.columnconfigure(0, weight=1)
        self.input_text = ttk.Entry(controls)
        self.input_text.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.input_text.bind("<Return>", lambda _event: self.ask())
        ttk.Button(controls, text="Ask", command=self.ask).grid(row=0, column=1)
        ttk.Button(controls, text="Search", command=self.search).grid(row=0, column=2, padx=(6, 0))
        ttk.Button(controls, text="Learn URL", command=self.learn_url).grid(row=0, column=3, padx=(6, 0))
        ttk.Button(controls, text="Add Memory", command=self.remember).grid(row=0, column=4, padx=(6, 0))
        ttk.Button(controls, text="Consolidate", command=self.consolidate).grid(row=0, column=5, padx=(6, 0))
        ttk.Button(controls, text="Reindex", command=self.reindex).grid(row=0, column=6, padx=(6, 0))
        ttk.Button(controls, text="Download Chat", command=self.download_chat).grid(row=0, column=7, padx=(6, 0))

        self.output = scrolledtext.ScrolledText(outer, wrap="word", height=18)
        self.output.grid(row=3, column=0, columnspan=3, sticky="nsew")

        memory_frame = ttk.LabelFrame(outer, text="Memories")
        memory_frame.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=(8, 0))
        memory_frame.columnconfigure(0, weight=1)
        memory_frame.rowconfigure(0, weight=1)
        self.memory_list = tk.Listbox(memory_frame, height=8)
        self.memory_list.grid(row=0, column=0, sticky="nsew")
        memory_scroll = ttk.Scrollbar(memory_frame, orient="vertical", command=self.memory_list.yview)
        memory_scroll.grid(row=0, column=1, sticky="ns")
        self.memory_list.configure(yscrollcommand=memory_scroll.set)
        memory_buttons = ttk.Frame(memory_frame)
        memory_buttons.grid(row=0, column=2, sticky="ns", padx=(8, 0))
        ttk.Button(memory_buttons, text="Refresh", command=self.refresh_memories).grid(row=0, column=0, sticky="ew")
        ttk.Button(memory_buttons, text="Delete Selected", command=self.delete_selected_memory).grid(row=1, column=0, sticky="ew", pady=(6, 0))

        ttk.Label(outer, textvariable=self.status_var).grid(row=6, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        self.memory_items: list[dict] = []
        self.refresh_memories()

    def _browse_vault(self) -> None:
        selected = filedialog.askdirectory(title="Select or create memory vault")
        if selected:
            self.vault_var.set(selected)

    def _memory(self) -> ObsidianMemory:
        return ObsidianMemory(Path(self.vault_var.get()).expanduser())

    def _agent(self) -> AdvancedGeminiAI:
        return AdvancedGeminiAI(vault=Path(self.vault_var.get()).expanduser(), model=self.model_var.get())

    def _append(self, text: str) -> None:
        self.output.insert("end", text.rstrip() + "\n\n")
        self.output.see("end")

    def _run_worker(self, status: str, worker: Worker) -> None:
        self.status_var.set(status)
        thread = threading.Thread(target=self._worker_target, args=(worker,), daemon=True)
        thread.start()

    def _worker_target(self, worker: Worker) -> None:
        try:
            result = worker()
        except Exception as exc:  # noqa: BLE001 - surface GUI worker failures to user.
            self.events.put(("error", str(exc)))
        else:
            self.events.put(("result", result))

    def _poll_events(self) -> None:
        while not self.events.empty():
            kind, text = self.events.get()
            if kind == "error":
                self.status_var.set("Error")
                messagebox.showerror("Obsidian Gemini AI", text)
            else:
                self._append(text)
                self.status_var.set("Ready")
        self.root.after(100, self._poll_events)

    def ask(self) -> None:
        message = self.input_text.get().strip()
        if not message:
            return
        self._append(f"You: {message}")
        self.input_text.delete(0, "end")
        self._run_worker(
            "Asking Gemini...",
            lambda: "AI: " + self._agent().ask(message, reflect=self.reflect_var.get(), deep=self.deep_var.get()),
        )

    def search(self) -> None:
        query = self.input_text.get().strip()
        if not query:
            return
        def worker() -> str:
            hits = self._memory().search(query)
            return "Search results:\n" + ("\n".join(format_hit(hit) for hit in hits) or "No matches")
        self._run_worker("Searching memory...", worker)

    def learn_url(self) -> None:
        url = self.input_text.get().strip()
        if not url:
            return
        self._run_worker("Learning URL...", lambda: f"Saved source note: {self._agent().learn_url(url)}")

    def remember(self) -> None:
        initial_body = self.input_text.get().strip()
        title = simpledialog.askstring("Add Memory", "Memory title:", parent=self.root)
        if not title:
            return
        body = simpledialog.askstring("Add Memory", "Memory body:", initialvalue=initial_body, parent=self.root)
        if not body:
            return
        tags_text = simpledialog.askstring("Add Memory", "Tags (comma-separated):", initialvalue="gui", parent=self.root) or "gui"
        tags = [tag.strip() for tag in tags_text.split(",") if tag.strip()]
        path = self._memory().remember(title, body, tags=tags)
        self._append(f"Saved memory: {path}")
        self.input_text.delete(0, "end")
        self.refresh_memories()

    def consolidate(self) -> None:
        self._run_worker("Consolidating memory...", lambda: "Consolidation:\n" + self._agent().consolidate())

    def reindex(self) -> None:
        count = self._memory().rebuild_index()
        self._append(f"Indexed {count} notes")
        self.refresh_memories()

    def refresh_memories(self) -> None:
        self.memory_list.delete(0, "end")
        self.memory_items = self._memory().list_memories()
        for item in self.memory_items:
            title = item.get("title") or item.get("path")
            tags = ", ".join(item.get("tags", [])) or "no tags"
            self.memory_list.insert("end", f"{title}  [{tags}]  {item.get('path')}")

    def delete_selected_memory(self) -> None:
        selection = self.memory_list.curselection()
        if not selection:
            messagebox.showinfo("Obsidian Gemini AI", "Select a memory to delete first.")
            return
        item = self.memory_items[selection[0]]
        relative_path = item.get("path")
        if not relative_path:
            return
        if not messagebox.askyesno("Delete Memory", f"Delete {relative_path}?"):
            return
        deleted = self._memory().delete_memory(relative_path)
        self._append(f"Deleted memory: {relative_path}" if deleted else f"Memory not found: {relative_path}")
        self.refresh_memories()

    def download_chat(self) -> None:
        destination = filedialog.asksaveasfilename(
            title="Download chat conversation",
            defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("Text", "*.txt"), ("All files", "*.*")],
        )
        if not destination:
            return
        content = self.output.get("1.0", "end").strip()
        Path(destination).write_text(content + "\n", encoding="utf-8")
        self.status_var.set(f"Saved chat to {destination}")


def main() -> None:
    root = tk.Tk()
    AssistantGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
