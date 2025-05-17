import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import whois, socket, csv, json, ipaddress, dns.resolver, requests, threading, queue

ENTITY_COLORS = {
    "IPv4": "orange",
    "Domain": "blue",
    "DNS": "yellow",
    "User": "limegreen",
    "Email": "purple",
    "IPv6": "navy",
    "Open Ports": "black"
}
ENTITY_ICONS = {
    "Email": "@",
    "Location": "\u25CF",
    "Server": "\U0001F5A5"  # 🖥️
}

class OSINTApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SC-IG - scanning")
        self.geometry("1200x700")
        self.resizable(False, False)
        self.active_frame = None
        self.graph = nx.DiGraph()
        self.node_positions = {}
        self.node_labels = {}
        self.node_types = {}
        self.logs = []
        self.selected_node = None
        self.result_queue = queue.Queue()
        self.create_menu()
        self.show_scanning()

    def create_menu(self):
        self.menu_frame = tk.Frame(self, bg="orange")
        self.menu_frame.pack(fill=tk.X)
        tk.Button(self.menu_frame, text="Libraries", command=self.show_library).pack(side=tk.LEFT)
        tk.Button(self.menu_frame, text="Help", command=self.show_help).pack(side=tk.LEFT)
        tk.Button(self.menu_frame, text="Exit", command=self.exit_tool).pack(side=tk.LEFT)
        self.tip_label = tk.Label(
            self.menu_frame,
            text="Tip: Drag and drop the options you want in the blank. Then double click to change target, and to start right click and click on 'Start Gathering' to run.",
            bg="orange"
        )
        self.tip_label.pack(side=tk.LEFT, padx=20)

    def exit_tool(self):
        self.destroy()

    def clear_frame(self):
        if self.active_frame:
            self.active_frame.destroy()

    def show_scanning(self):
        self.clear_frame()
        self.active_frame = tk.Frame(self, bg="#333")
        self.active_frame.pack(fill=tk.BOTH, expand=True)

        # Sidebar
        sidebar = tk.Frame(self.active_frame, width=150, bg="#444")
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        tk.Label(sidebar, text="Entities", bg="#444", fg="white", font=("Arial", 12, "bold")).pack(pady=5)
        for ent, color in ENTITY_COLORS.items():
            icon = ENTITY_ICONS.get(ent, "")
            tk.Label(sidebar, text=f"{icon} {ent}", bg=color, fg="white", width=15, pady=3).pack(pady=2)

        # Main graph area
        main_area = tk.Frame(self.active_frame, bg="#222")
        main_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Entry and scan button
        input_frame = tk.Frame(main_area, bg="#222")
        input_frame.pack(fill=tk.X, pady=5)
        tk.Label(input_frame, text="Target (Domain or IP):", bg="#222", fg="white").pack(side=tk.LEFT, padx=5)
        self.target_entry = tk.Entry(input_frame, width=40)
        self.target_entry.pack(side=tk.LEFT, padx=5)
        self.scan_btn = tk.Button(input_frame, text="Start Gathering", command=self.run_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        tk.Button(input_frame, text="Export", command=self.export_menu).pack(side=tk.LEFT, padx=5)

        # Graph canvas
        self.fig, self.ax = plt.subplots(figsize=(7, 5))
        self.fig.patch.set_facecolor('#222')
        self.ax.set_facecolor('#222')
        self.canvas = FigureCanvasTkAgg(self.fig, master=main_area)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self.canvas.mpl_connect("button_press_event", self.on_graph_click)
        self.canvas.mpl_connect("motion_notify_event", self.on_graph_drag)
        self.canvas.mpl_connect("button_release_event", self.on_graph_release)
        self._dragging_node = None

        # Logs
        log_frame = tk.Frame(main_area)
        log_frame.pack(fill=tk.X)
        tk.Label(log_frame, text="Logs").pack(anchor="w")
        self.log_text = tk.Text(log_frame, height=4)
        self.log_text.pack(fill=tk.X)

        # Progress bar
        self.progress = ttk.Progressbar(main_area, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(fill=tk.X, pady=5)

    def show_library(self):
        self.clear_frame()
        self.active_frame = tk.Frame(self, bg="#eee")
        self.active_frame.pack(fill=tk.BOTH, expand=True)
        tk.Button(self.active_frame, text="Back to scanning", command=self.show_scanning).pack(anchor="w", pady=10, padx=10)
        tk.Label(self.active_frame, text="SC-IG - Library", font=("Arial", 16, "bold"), bg="#eee").pack(pady=10)
        grid = tk.Frame(self.active_frame, bg="#eee")
        grid.pack()
        for i in range(1):
            for j in range(1):
                f = tk.Frame(grid, width=200, height=120, bg="#bbb", padx=10, pady=10)
                f.grid(row=i, column=j, padx=10, pady=10)
                tk.Label(f, text="Python Library", bg="#bbb").pack()
                tk.Label(f, text="uses whois, socket, ipaddress,\n dns.resolver, requests", bg="#bbb").pack()
        f = tk.Frame(grid, width=200, height=120, bg="#bbb", padx=10, pady=10)

    def show_help(self):
        self.clear_frame()
        self.active_frame = tk.Frame(self, bg="#eee")
        self.active_frame.pack(fill=tk.BOTH, expand=True)
        tk.Button(self.active_frame, text="Back to scanning", command=self.show_scanning).pack(anchor="w", pady=10, padx=10)
        tk.Label(self.active_frame, text="SC-IG - Help", font=("Arial", 16, "bold"), bg="#eee").pack(pady=10)
        tk.Label(self.active_frame, text="""SC-IG : SC Information Gather Tool
        This tool uses for information gathering about your target(Domain and IP Add)
        Here is how you can use it, it is easy to use: 
        1. Enter your target Domain or IP Address
        2. Enter 'Start Gathernig' button to start
        3.then you can save the information by clicking on Export button.
        
        ! : but this is not the full version of the tool, so that mean the tool dosen't
        giving you the full information, you can buy it from :
        
        https://t.me/Zero_Strike_SC""", bg="#eee", font=("Arial", 12)).pack(pady=50)

    def log(self, msg):
        self.logs.append(msg)
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(tk.END, "\n".join(self.logs[-5:]))

    # --- UNFREEZER: Threaded scan ---
    def run_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a target domain or IP.")
            return
        self.progress['value'] = 0
        self.log(f"Scanning {target} ...")
        self.graph.clear()
        self.node_types.clear()
        self.node_labels.clear()
        self.scan_btn.config(state='disabled')
        scan_thread = threading.Thread(target=self.scan_thread_function, args=(target,))
        scan_thread.daemon = True
        scan_thread.start()
        self.after(100, self.process_queue)

    def scan_thread_function(self, target):
        try:
            entity_type = self.detect_entity_type(target)
            self.graph.add_node(target)
            self.node_types[target] = entity_type
            self.node_labels[target] = target

            # WHOIS info
            try:
                self.result_queue.put(("progress", 10))
                self.result_queue.put(("log", "Performing WHOIS lookup..."))
                w = whois.whois(target)
                if w.domain_name:
                    dom = w.domain_name if isinstance(w.domain_name, str) else w.domain_name[0]
                    self.add_entity(dom, "Domain", target)
                if w.emails:
                    emails = w.emails if isinstance(w.emails, list) else [w.emails]
                    for email in emails:
                        self.add_entity(email, "Email", target)
                if w.name:
                    self.add_entity(w.name, "User", target)
            except Exception as e:
                self.result_queue.put(("log", f"WHOIS lookup failed: {e}"))

            # DNS records
            try:
                self.result_queue.put(("progress", 30))
                self.result_queue.put(("log", "Getting DNS records..."))
                for record_type in ['A', 'AAAA', 'MX', 'NS']:
                    try:
                        answers = dns.resolver.resolve(target, record_type)
                        for rdata in answers:
                            val = str(rdata)
                            if record_type == "A":
                                self.add_entity(val, "IPv4", target)
                            elif record_type == "AAAA":
                                self.add_entity(val, "IPv6", target)
                            else:
                                self.add_entity(val, "DNS", target)
                    except Exception:
                        continue
            except Exception as e:
                self.result_queue.put(("log", f"DNS lookup failed: {e}"))

            # Host info (IP, open ports)
            try:
                self.result_queue.put(("progress", 50))
                self.result_queue.put(("log", "Resolving host info..."))
                ip = socket.gethostbyname(target)
                self.add_entity(ip, "IPv4", target)
                open_ports = []
                for port in [80, 443, 22, 21, 8080, 20, 7]:
                    try:
                        s = socket.socket()
                        s.settimeout(0.5)
                        s.connect((ip, port))
                        open_ports.append(port)
                        s.close()
                    except:
                        pass
                if open_ports:
                    port_str = ",".join(str(p) for p in open_ports)
                    self.add_entity(f"{ip}:{port_str}", "Open Ports", ip)
            except Exception as e:
                self.result_queue.put(("log", f"Host info failed: {e}"))

            self.result_queue.put(("progress", 100))
            self.result_queue.put(("log", "Scan complete."))
            self.result_queue.put(("done", True))

        except Exception as e:
            self.result_queue.put(("log", f"Error during scan: {e}"))
            self.result_queue.put(("progress", 100))
            self.result_queue.put(("done", True))

    def process_queue(self):
        try:
            while True:
                message = self.result_queue.get_nowait()
                if message[0] == "progress":
                    self.progress['value'] = message[1]
                elif message[0] == "log":
                    self.log(message[1])
                elif message[0] == "done":
                    self.scan_btn.config(state='normal')
                    self.draw_graph()
                    return
        except queue.Empty:
            self.after(100, self.process_queue)

    def add_entity(self, value, entity_type, parent):
        if not value or value in self.graph.nodes:
            return
        self.graph.add_node(value)
        self.graph.add_edge(parent, value)
        self.node_types[value] = entity_type
        self.node_labels[value] = value

    def detect_entity_type(self, value):
        try:
            ipaddress.ip_address(value)
            return "IPv4" if ":" not in value else "IPv6"
        except:
            if "@" in value:
                return "Email"
            elif value.isdigit() and len(value) > 6:
                return "User"
            elif "." in value:
                return "Domain"
            return "User"

    def is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except:
            return False

    def draw_graph(self):
        self.ax.clear()
        self.fig.patch.set_facecolor('#222')
        self.ax.set_facecolor('#222')
        if len(self.graph.nodes) == 0:
            self.canvas.draw()
            return
        pos = nx.spring_layout(self.graph, k=0.7, seed=42)
        self.node_positions = pos
        for node in self.graph.nodes:
            ent_type = self.node_types.get(node, "Domain")
            nx.draw_networkx_nodes(self.graph, pos, nodelist=[node],
                                   node_color=ENTITY_COLORS.get(ent_type, "gray"),
                                   ax=self.ax, node_size=1200)
        nx.draw_networkx_edges(self.graph, pos, ax=self.ax, arrows=True, arrowstyle="-|>")
        labels = {}
        for node in self.graph.nodes:
            ent_type = self.node_types.get(node, "Domain")
            icon = ENTITY_ICONS.get(ent_type, "")
            labels[node] = f"{icon} {node}" if icon else node
        nx.draw_networkx_labels(self.graph, pos, labels=labels, ax=self.ax, font_color="black")
        self.ax.axis("off")
        self.canvas.draw()

    # --- Graph interactivity: drag and context menu ---
    def on_graph_click(self, event):
        if event.button == 3:  # Right click
            node = self.get_node_at_pos(event)
            if node:
                self.selected_node = node
                self.show_node_context_menu(event)
        elif event.button == 1:  # Left click
            node = self.get_node_at_pos(event)
            if node:
                self._dragging_node = node
                self._drag_offset = (event.xdata, event.ydata)

    def on_graph_drag(self, event):
        if self._dragging_node and event.xdata and event.ydata:
            self.node_positions[self._dragging_node] = (event.xdata, event.ydata)
            self.draw_graph_with_positions()

    def on_graph_release(self, event):
        self._dragging_node = None

    def draw_graph_with_positions(self):
        self.ax.clear()
        self.fig.patch.set_facecolor('#222')
        self.ax.set_facecolor('#222')
        pos = self.node_positions
        for node in self.graph.nodes:
            ent_type = self.node_types.get(node, "Domain")
            nx.draw_networkx_nodes(self.graph, pos, nodelist=[node],
                                   node_color=ENTITY_COLORS.get(ent_type, "gray"),
                                   ax=self.ax, node_size=1200)
        nx.draw_networkx_edges(self.graph, pos, ax=self.ax, arrows=True, arrowstyle="-|>")
        labels = {}
        for node in self.graph.nodes:
            ent_type = self.node_types.get(node, "Domain")
            icon = ENTITY_ICONS.get(ent_type, "")
            labels[node] = f"{icon} {node}" if icon else node
        nx.draw_networkx_labels(self.graph, pos, labels=labels, ax=self.ax, font_color="black")
        self.ax.axis("off")
        self.canvas.draw()

    def get_node_at_pos(self, event):
        if not event.xdata or not event.ydata:
            return None
        for node, (x, y) in self.node_positions.items():
            if abs(event.xdata - x) < 0.1 and abs(event.ydata - y) < 0.1:
                return node
        return None

    def show_node_context_menu(self, event):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Edit Entity", command=self.edit_selected_node)
        menu.add_command(label="Delete Entity", command=self.delete_selected_node)
        menu.post(int(self.winfo_pointerx()), int(self.winfo_pointery()))

    def edit_selected_node(self):
        if not self.selected_node:
            return
        new_val = simpledialog.askstring("Edit Entity", "New value:", initialvalue=self.selected_node)
        if new_val:
            ent_type = self.node_types.get(self.selected_node, "Domain")
            self.graph = nx.relabel_nodes(self.graph, {self.selected_node: new_val})
            self.node_types[new_val] = ent_type
            self.node_labels[new_val] = new_val
            del self.node_types[self.selected_node]
            del self.node_labels[self.selected_node]
            self.selected_node = new_val
            self.draw_graph()

    def delete_selected_node(self):
        if not self.selected_node:
            return
        self.graph.remove_node(self.selected_node)
        del self.node_types[self.selected_node]
        del self.node_labels[self.selected_node]
        self.selected_node = None
        self.draw_graph()

    # --- Export features ---
    def export_menu(self):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Export as CSV", command=self.export_csv)
        menu.add_command(label="Export as JSON", command=self.export_json)
        menu.post(int(self.winfo_pointerx()), int(self.winfo_pointery()))

    def export_csv(self):
        file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if not file:
            return
        with open(file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Entity", "Type"])
            for node in self.graph.nodes:
                writer.writerow([node, self.node_types.get(node, "")])
        messagebox.showinfo("Export", f"Exported as CSV: {file}")

    def export_json(self):
        file = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if not file:
            return
        data = []
        for node in self.graph.nodes:
            data.append({"entity": node, "type": self.node_types.get(node, "")})
        with open(file, "w") as f:
            json.dump(data, f, indent=2)
        messagebox.showinfo("Export", f"Exported as JSON: {file}")

if __name__ == "__main__":
    app = OSINTApp()
    app.mainloop()
