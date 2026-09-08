/// NaxDarks Linux TCP Listener
/// Soporta dos modos de transporte para el agente Linux:
///   bind  (pivot): el agente hace bind y espera que el parent conecte
///   connect (directo): el agente conecta al C2 — el listener escucha en c2_port

function ListenerUI(mode_create)
{
    let spacer1 = form.create_vspacer();

    // ===== Bind mode config (para pivot) =====

    let groupBindInner = form.create_gridlayout();
    let labelBindHost = form.create_label("Bind host:");
    let textBindHost  = form.create_textline("0.0.0.0");
    if (!mode_create) { textBindHost.setReadOnly(true); }
    let labelBindPort = form.create_label("Bind port:");
    let spinBindPort  = form.create_spin();
    spinBindPort.setRange(1, 65535);
    spinBindPort.setValue(4444);
    if (!mode_create) { spinBindPort.setEnabled(false); }
    groupBindInner.addWidget(labelBindHost, 0, 0); groupBindInner.addWidget(textBindHost, 0, 1);
    groupBindInner.addWidget(labelBindPort, 1, 0); groupBindInner.addWidget(spinBindPort, 1, 1);
    let groupBindPanel = form.create_panel();
    groupBindPanel.setLayout(groupBindInner);
    let groupBind = form.create_groupbox("Mode pivot (bind)", false);
    groupBind.setPanel(groupBindPanel);

    // ===== Connect mode config (para directo al C2) =====

    let groupConnInner = form.create_gridlayout();
    let labelC2Host  = form.create_label("C2 host:");
    let comboC2Host  = form.create_combo();
    comboC2Host.setEnabled(mode_create);
    for (let item of ax.interfaces()) comboC2Host.addItem(item);
    let labelC2Port = form.create_label("C2 port:");
    let spinC2Port  = form.create_spin();
    spinC2Port.setRange(1, 65535);
    spinC2Port.setValue(5555);
    if (!mode_create) { spinC2Port.setEnabled(false); }
    groupConnInner.addWidget(labelC2Host, 0, 0); groupConnInner.addWidget(comboC2Host, 0, 1);
    groupConnInner.addWidget(labelC2Port, 1, 0); groupConnInner.addWidget(spinC2Port, 1, 1);
    let groupConnPanel = form.create_panel();
    groupConnPanel.setLayout(groupConnInner);
    let groupConn = form.create_groupbox("Mode Connect (direct)", false);
    groupConn.setPanel(groupConnPanel);

    // ===== Encryption key =====

    let labelKey = form.create_label("Encryption key:");
    let textKey  = form.create_textline(ax.random_string(32, "hex"));
    textKey.setEnabled(mode_create);
    let btnKey = form.create_button("Generate");
    btnKey.setEnabled(mode_create);

    form.connect(btnKey, "clicked", function() {
        textKey.setText(ax.random_string(32, "hex"));
    });

    // agent_crc hardcodeado — no visible para el operador
    let hiddenCrc = form.create_textline("deadbeef");

    let spacer2 = form.create_vspacer();

    let layout = form.create_gridlayout();
    layout.addWidget(spacer1,    0, 0, 1, 3);
    layout.addWidget(groupBind,  1, 0, 1, 3);
    layout.addWidget(groupConn,  2, 0, 1, 3);
    layout.addWidget(labelKey,   3, 0, 1, 1);
    layout.addWidget(textKey,    3, 1, 1, 1);
    layout.addWidget(btnKey,     3, 2, 1, 1);
    layout.addWidget(spacer2,    4, 0, 1, 3);

    let container = form.create_container();
    container.put("bind_host",   textBindHost);
    container.put("bind_port",   spinBindPort);
    container.put("c2_host",     comboC2Host);
    container.put("c2_port",     spinC2Port);
    container.put("encrypt_key", textKey);
    container.put("agent_crc",   hiddenCrc);

    let panel = form.create_panel();
    panel.setLayout(layout);

    return {
        ui_panel:     panel,
        ui_container: container,
        ui_height:    650,
        ui_width:     650
    };
}
