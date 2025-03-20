import tkinter as tk
from tkinter import ttk
from utilities import *
import scripts  # Import the scripts module

# List of possible log locations
LOG_PATHS = [
    r"C:\Program Files\ATERA Networks\AteraAgent\Agent\logs",  # Always exists
    r"C:\Program Files\ATERA Networks\AteraAgent\Agent\packages\AgentPackageMonitoring",
    r"C:\Program Files\ATERA Networks\AteraAgent\Agent\packages\AgentPackageSystemTools",
    r"C:\Program Files\ATERA Networks\AteraAgent\Agent\packages\AgentPackageOsUpdates",
    r"C:\Program Files\ATERA Networks\AteraAgent\Agent\packages\AgentPackageInternalPoller",
]

def execute_script(script_name):
    """Fetch the script content from scripts.py, run it, and update the text widget."""
    
    # Dynamically retrieve the script content using getattr
    script_content = getattr(scripts, script_name, None)  
    
    if script_content:
        result = run_script(script_content)  # Run the actual script content
    else:
        result = f"Error: Script '{script_name}' not found in scripts.py"
    
    feedback_text.delete(1.0, tk.END)  # Clear previous output
    feedback_text.insert(tk.END, result)  # Insert new output

def create_log_tabs(parent_tab):
    """Dynamically create log tabs based on available logs."""
    log_notebook = ttk.Notebook(parent_tab)
    log_notebook.pack(expand=True, fill="both")

    log_found = False

    for log_folder in LOG_PATHS:
        log_file = find_latest_log(log_folder)
        if log_file:
            log_found = True
            log_name = os.path.basename(os.path.dirname(log_file))
            if log_name == "logs":
                log_name = "Agent log"

            log_tab = ttk.Frame(log_notebook)
            log_notebook.add(log_tab, text=log_name)

            scrollbar = tk.Scrollbar(log_tab, orient="vertical")
            scrollbar.pack(side="right", fill="y")

            log_text = tk.Text(log_tab, wrap="word", yscrollcommand=scrollbar.set)
            log_text.pack(fill="both", expand=True)
            scrollbar.config(command=log_text.yview)

            log_content = read_log_file(log_file)
            log_text.insert(tk.END, log_content)

    if not log_found:
        label = ttk.Label(parent_tab, text="No log files found.", font=("Arial", 12))
        label.pack(pady=20)


# Create the main window
root = tk.Tk()
root.title("Atera Multitool")
logo = tk.PhotoImage(file="ateralogo.png")
root.iconphoto(False, logo)
root.geometry("950x500")  # Set window size

# Define the Notebook (tabs)
tabs = ttk.Notebook(root)
tabs.pack(expand=True, fill="both")

tab1 = ttk.Frame(tabs)
tabs.add(tab1, text="Agent Information")

tab2 = ttk.Frame(tabs)
tabs.add(tab2, text="Agent Actions")

tab3 = ttk.Frame(tabs)
tabs.add(tab3, text = "Log Exceptions")

tab4 = ttk.Frame(tabs)
tabs.add(tab4, text = "Read me!")

# Tab Frames
###############################################

# Tab 1 Frames

agent_inf_frame = tk.Frame(tab1, bd=1, relief="solid")
agent_inf_frame.pack(side="left", fill="both", expand=True)

os_inf_frame = tk.Frame(tab1, bd=1, relief="solid")
os_inf_frame.pack(side="right", fill="both", expand=True)

# Tab 2 Frames

action_buttons_frame = tk.Frame(tab2, bd=1, relief="solid")
action_buttons_frame.pack(side = "top", fill= "x", expand = False)

action_feedbacks = tk.Frame(tab2, bd = 1, relief = "solid")
action_feedbacks.pack(side = "bottom", fill= "both", expand = True )

# Tab 3's nested tabs

create_log_tabs(tab3)

# Tab 4 text widget

info_frame = tk.Frame(tab4, bd=1, relief="solid")
info_frame.pack(fill="both", expand=True)

info_scrollbar = tk.Scrollbar(info_frame, orient="vertical")
info_scrollbar.pack(side="right", fill="y")

# Contents and Buttons
###############################################

# Tab 1's buttons and stuffs

# Agent Info labels
# Label to display the Agent version
version_text = tk.StringVar(value=f"Agent version: {get_agent_version()}")
version_label = ttk.Label(agent_inf_frame, textvariable=version_text, anchor="w", font=("Arial", 12))
version_label.pack(padx=10, pady=10, anchor="w")  # Moved padding to pack()

# Label o display the Service's Run As user
service_text = tk.StringVar(value=f"Service user: {get_agent_service()}")
service_label = ttk.Label(agent_inf_frame, textvariable=service_text, anchor="w", font=("Arial", 12))
service_label.pack(padx=10, pady=10, anchor="w")

# Label to display AccountID
account_id_text = tk.StringVar(value=f"Account ID: {get_account_id()}")
account_id_label = ttk.Label(agent_inf_frame, textvariable=account_id_text, anchor="w", font=("Arial", 12))
account_id_label.pack(padx=10, pady=10, anchor="w")

# OS info labels
# Label to display the OS version
os_inf_text = tk.StringVar(value=get_os_info())
os_inf_label = ttk.Label(os_inf_frame, textvariable=os_inf_text, anchor="w", font=("Arial", 12))
os_inf_label.pack(padx=10, pady=10, anchor="w")

# SSL Version Label
ssl_version_text = tk.StringVar(value=f"SSL Version: {get_ssl_version()}")
ssl_version_label = ttk.Label(os_inf_frame, textvariable=ssl_version_text, anchor="w", font=("Arial", 12))
ssl_version_label.pack(padx=10, pady=5, anchor="w")

# TLS Version Label
tls_version_text = tk.StringVar(value=f"TLS Version: {get_tls_version()}")
tls_version_label = ttk.Label(os_inf_frame, textvariable=tls_version_text, anchor="w", font=("Arial", 12))
tls_version_label.pack(padx=10, pady=5, anchor="w")

# FIPS enable check
fips_enable = tk.StringVar(value=f"FIPS: {get_fips()}")
fips_enable_label = ttk.Label(os_inf_frame, textvariable=fips_enable, anchor="w", font=("Arial", 12))
fips_enable_label.pack(padx=10, pady=5, anchor="w")

# .NET Framework Version Label
net_version_text = tk.StringVar(value=f".NET Framework: {get_net_version()}")
net_version_label = ttk.Label(os_inf_frame, textvariable=net_version_text, anchor="w", font=("Arial", 12))
net_version_label.pack(padx=10, pady=5, anchor="w")

# .NET Core Versions Label
core_versions = get_core_version()
core_version_text = tk.StringVar(value=f".NET Core Versions: {', '.join(core_versions) if isinstance(core_versions, list) else core_versions}")
core_version_label = ttk.Label(os_inf_frame, textvariable=core_version_text, anchor="w", font=("Arial", 12))
core_version_label.pack(padx=10, pady=5, anchor="w")

export_button = tk.Button( os_inf_frame, text= "Export all", command = export_info, activeforeground="lightgray", disabledforeground="white", anchor =  "center")
export_button.pack(side = "bottom", fill="x", padx=10, pady=10)

# Tab 2's buttons and stuffs

run_connection = tk.Button(action_buttons_frame, text= "Check connections", command=lambda: execute_script("script_connection"), activeforeground="lightgray", disabledforeground="white", anchor = "w")
run_connection.pack(side = "left", padx=1, pady=1)

run_packages = tk.Button(action_buttons_frame, text= "Check package availability", command=lambda: execute_script("script_packages"), activeforeground="lightgray", disabledforeground="white", anchor = "w")
run_packages.pack(side = "left", padx=1, pady=1)

run_cleanup = tk.Button(action_buttons_frame, text= "Run cleanup", command=lambda: execute_script("script_cleanup"), activeforeground="lightgray", disabledforeground="white", anchor = "w")
run_cleanup.pack(side = "left", padx=1, pady=1)

run_splashtop = tk.Button(action_buttons_frame, text= "Remove Splashtop", command=lambda: execute_script("script_splashtop"), activeforeground="lightgray", disabledforeground="white", anchor = "w")
run_splashtop.pack(side = "left", padx=1, pady=1)

run_ndiscovery = tk.Button(action_buttons_frame, text= "Remove N.Discovery", command=lambda: execute_script("script_ndiscovery"), activeforeground="lightgray", disabledforeground="white", anchor = "w")
run_ndiscovery.pack(side = "left", padx=1, pady=1)

run_helpdesk = tk.Button(action_buttons_frame, text= "Remove Helpdesk Agent", command=lambda: execute_script("script_helpdesk"), activeforeground="lightgray", disabledforeground="white", anchor = "w")
run_helpdesk.pack(side = "left", padx=1, pady=1)

run_sccm = tk.Button(action_buttons_frame, text= "Remove SCCM", command=lambda: execute_script("script_sccm"), activeforeground="lightgray", disabledforeground="white", anchor = "w")
run_sccm.pack(side = "left", padx=1, pady=1)

run_notifs = tk.Button(action_buttons_frame, text= "Fix Reboot Notifications", command=lambda: execute_script("script_rebootnotify"), activeforeground="lightgray", disabledforeground="white", anchor = "w")
run_notifs.pack(side = "left", padx=1, pady=1)

# Text widget and scrollbar
scrollbar = tk.Scrollbar(action_feedbacks, orient="vertical")
scrollbar.pack(side="right", fill="y")

feedback_text = tk.Text(action_feedbacks, wrap="word", yscrollcommand=scrollbar.set)
feedback_text.pack(fill="both", expand=True)

scrollbar.config(command=feedback_text.yview)

#Tab 4's widgets

info_text = tk.Text(info_frame, wrap="word", yscrollcommand=info_scrollbar.set, font=("Arial", 11))
info_text.pack(fill="both", expand=True)

# Insert the disclaimer text and set it to read-only
info_text.insert("1.0", disclaimer)
info_text.config(state="disabled")  # Make the text read-only

# Link scrollbar to text widget
info_scrollbar.config(command=info_text.yview)

# End
# Run the application
root.mainloop()
