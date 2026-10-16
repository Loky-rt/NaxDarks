/// NaxDarks Graph C2 — Azure Blob Storage listener

function ListenerUI(mode_create)
{
    let labelAccount = form.create_label("Storage Account:");
    let editAccount = form.create_textline();
    editAccount.setPlaceholder("mystorageaccount");
    editAccount.setEnabled(mode_create);

    let labelKey = form.create_label("Storage Key:");
    let editKey = form.create_textline();
    editKey.setPlaceholder("base64-encoded storage account key");
    editKey.setEnabled(mode_create);

    let labelContainer = form.create_label("Container Name:");
    let editContainer = form.create_textline();
    editContainer.setPlaceholder("adaptix-c2");
    editContainer.setText("adaptix-c2");

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
    layout.addWidget(labelAccount,      0, 0);
    layout.addWidget(editAccount,       0, 1);
    layout.addWidget(labelKey,          1, 0);
    layout.addWidget(editKey,           1, 1);
    layout.addWidget(labelContainer,    2, 0);
    layout.addWidget(editContainer,     2, 1);
    layout.addWidget(labelPoll,         3, 0);
    layout.addWidget(spinPoll,          3, 1);
    layout.addWidget(labelEncKey,       4, 0);
    layout.addWidget(editEncKey,        4, 1);
    layout.addWidget(labelPollAttempts, 5, 0);
    layout.addWidget(spinPollAttempts,  5, 1);
    layout.addWidget(labelPollMs,       6, 0);
    layout.addWidget(spinPollMs,        6, 1);

    let container = form.create_container();
    container.put("storage_account",  editAccount);
    container.put("storage_key",      editKey);
    container.put("container_name",   editContainer);
    container.put("poll_interval",    spinPoll);
    container.put("encrypt_key",      editEncKey);
    container.put("poll_attempts",    spinPollAttempts);
    container.put("poll_interval_ms", spinPollMs);

    let panel = form.create_panel();
    panel.setLayout(layout);

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 360,
        ui_width: 500
    }
}
