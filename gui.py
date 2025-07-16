import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import requests
import threading

class ShellCheckerApp:
    def __init__(self, master):
        # Initialize the main window
        self.master = master
        master.title("b374k Shell Checker")
        master.geometry("800x600") # Set initial window size
        master.configure(bg="#2c3e50") # Dark background for a modern look

        # Configure grid weights for responsive layout
        master.grid_rowconfigure(0, weight=0)
        master.grid_rowconfigure(1, weight=1)
        master.grid_columnconfigure(0, weight=1)

        # --- Header Frame ---
        self.header_frame = tk.Frame(master, bg="#34495e", bd=5, relief="raised")
        self.header_frame.pack(fill="x", pady=10, padx=10)

        self.title_label = tk.Label(self.header_frame, text="b374k Shell Checker",
                                    font=("Inter", 24, "bold"), fg="#ecf0f1", bg="#34495e")
        self.title_label.pack(pady=10)

        # --- Control Frame ---
        self.control_frame = tk.Frame(master, bg="#34495e", bd=3, relief="groove")
        self.control_frame.pack(fill="x", pady=5, padx=10)

        # File selection
        self.file_label = tk.Label(self.control_frame, text="Selected File:", font=("Inter", 12), fg="#ecf0f1", bg="#34495e")
        self.file_label.pack(side="left", padx=10, pady=5)

        self.file_path_entry = tk.Entry(self.control_frame, width=50, font=("Inter", 10), bd=2, relief="sunken")
        self.file_path_entry.pack(side="left", padx=5, pady=5, expand=True, fill="x")

        self.browse_button = tk.Button(self.control_frame, text="Browse", command=self.browse_file,
                                       font=("Inter", 10, "bold"), bg="#2ecc71", fg="#ffffff",
                                       activebackground="#27ae60", activeforeground="#ffffff",
                                       relief="raised", bd=3, cursor="hand2")
        self.browse_button.pack(side="left", padx=5, pady=5)

        self.start_button = tk.Button(self.control_frame, text="Start Check", command=self.start_check_thread,
                                      font=("Inter", 10, "bold"), bg="#3498db", fg="#ffffff",
                                      activebackground="#2980b9", activeforeground="#ffffff",
                                      relief="raised", bd=3, cursor="hand2")
        self.start_button.pack(side="left", padx=5, pady=5)

        # --- Output Frame ---
        self.output_frame = tk.Frame(master, bg="#2c3e50")
        self.output_frame.pack(fill="both", expand=True, pady=10, padx=10)
        self.output_frame.grid_rowconfigure(0, weight=1)
        self.output_frame.grid_columnconfigure(0, weight=1)

        self.output_text = scrolledtext.ScrolledText(self.output_frame, wrap=tk.WORD, width=100, height=20,
                                                     font=("Consolas", 10), bg="#1c2833", fg="#ecf0f1",
                                                     insertbackground="#ecf0f1", bd=2, relief="sunken")
        self.output_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Add tags for colored output
        self.output_text.tag_config("success", foreground="#2ecc71") # Green for HIDUP
        self.output_text.tag_config("failure", foreground="#e74c3c") # Red for MATI!
        self.output_text.tag_config("info", foreground="#3498db")    # Blue for info messages

        # Global variables for the checking process
        self.is_checking = False

    def browse_file(self):
        # Open a file dialog to select the URL list file
        file_path = filedialog.askopenfilename(
            title="Select URL List File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, file_path)
            self.output_text.insert(tk.END, f"File selected: {file_path}\n", "info")
            self.output_text.see(tk.END)

    def start_check_thread(self):
        # Start the checking process in a separate thread to keep the GUI responsive
        if self.is_checking:
            messagebox.showinfo("Info", "Checking is already in progress.")
            return

        file_path = self.file_path_entry.get()
        if not file_path:
            messagebox.showwarning("Warning", "Please select a file first.")
            return

        self.output_text.delete(1.0, tk.END) # Clear previous output
        self.output_text.insert(tk.END, "Starting check...\n", "info")
        self.output_text.see(tk.END)

        self.is_checking = True
        self.start_button.config(state=tk.DISABLED) # Disable button during check
        # Create and start a new thread for the check_urls method
        threading.Thread(target=self.check_urls, args=(file_path,)).start()

    def check_urls(self, file_path):
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()

            # Sort lines as in the original Perl script
            lines.sort()

            user_agent = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)"
            headers = {'User-Agent': user_agent}
            timeout = 10

            for http_url in lines:
                # Clean up the URL string
                http_url = http_url.strip()

                if http_url.startswith("http://") or http_url.startswith("https://"):
                    try:
                        # Perform the HTTP GET request
                        response = requests.get(http_url, headers=headers, timeout=timeout)
                        content = response.text

                        # Check for "b374k" in the content
                        if "b374k" in content:
                            self.output_text.insert(tk.END, f"HIDUP -> checking : {http_url}\n", "success")
                        else:
                            self.output_text.insert(tk.END, f"MATI! -> checking : {http_url}\n", "failure")
                    except requests.exceptions.RequestException as e:
                        # Handle request errors (e.g., connection refused, timeout)
                        self.output_text.insert(tk.END, f"ERROR -> {http_url} : {e}\n", "failure")
                    except Exception as e:
                        # Catch any other unexpected errors
                        self.output_text.insert(tk.END, f"UNEXPECTED ERROR -> {http_url} : {e}\n", "failure")
                else:
                    self.output_text.insert(tk.END, f"SKIPPING -> {http_url} : Not a valid HTTP/HTTPS URL\n", "info")
                self.output_text.see(tk.END) # Scroll to the end of the text widget

        except FileNotFoundError:
            messagebox.showerror("Error", f"File not found: {file_path}")
            self.output_text.insert(tk.END, f"Error: File not found: {file_path}\n", "failure")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            self.output_text.insert(tk.END, f"An unexpected error occurred: {e}\n", "failure")
        finally:
            self.is_checking = False
            self.start_button.config(state=tk.NORMAL) # Re-enable button after check
            self.output_text.insert(tk.END, "\nCheck finished.\n", "info")
            self.output_text.see(tk.END)

# Main part of the script to run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = ShellCheckerApp(root)
    root.mainloop()
